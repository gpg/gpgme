/* trustlist.c -  key listing
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"

#define my_isdigit(a) ( (a) >='0' && (a) <= '9' )

struct gpgme_trust_item_s {
    int level;
    char keyid[16+1];
    int type;   
    char ot[2];
    char val[2];
    char *name;
};


static GpgmeTrustItem
trust_item_new (void)
{
    GpgmeTrustItem item;

    item = xtrycalloc (1, sizeof *item);
    return item;
}



static void
trustlist_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;

    switch (code) {
      case STATUS_EOF:
        break;

      default:
        break;
    }
}



/* 
 * This handler is used to parse the output of --list-trust-path:
 * Format:
 *   level:keyid:type:recno:ot:val:mc:cc:name:
 * With TYPE = U for a user ID
 *	       K for a key
 * The RECNO is either the one of the dir record or the one of the uid record.
 * OT is the the usual trust letter and only availabel on K lines.
 * VAL is the calcualted validity
 * MC is the marginal trust counter and only available on U lines
 * CC is the same for the complete count
 * NAME ist the username and only printed on U lines
 */
static void
trustlist_colon_handler ( GpgmeCtx ctx, char *line )
{
    char *p, *pend;
    int field = 0;
    GpgmeTrustItem item = NULL;
    struct trust_queue_item_s *q, *q2;

    if ( ctx->out_of_core )
        return;
    if (!line)
        return; /* EOF */

    for (p = line; p; p = pend) {
        field++;
        pend = strchr (p, ':');
        if (pend) 
            *pend++ = 0;

        switch (field) {
          case 1: /* level */
            q = xtrymalloc ( sizeof *q );
            if ( !q ) {
                ctx->out_of_core = 1;
                return;
            }
            q->next = NULL;
            q->item = item = trust_item_new ();
            if (!q->item) {
                xfree (q);
                ctx->out_of_core = 1;
                return;
            }
            /* fixme: lock queue, keep a tail pointer */
            if ( !(q2 = ctx->trust_queue) )
                ctx->trust_queue = q;
            else {
                for ( ; q2->next; q2 = q2->next )
                    ;
                q2->next = q;
            }
            /* fixme: unlock queue */
            item->level = atoi (p);
            break;
          case 2: /* long keyid */
            if ( strlen (p) == DIM(item->keyid)-1 )
                strcpy (item->keyid, p);
            break;
          case 3: /* type */
            item->type = *p == 'K'? 1 : *p == 'U'? 2 : 0;
            break;
          case 5: /* owner trust */
            item->ot[0] = *p;
            item->ot[1] = 0;
            break;
          case 6: /* validity */
            item->val[0] = *p;
            item->val[1] = 0;
            break;
          case 10: /* user ID */
            item->name = xtrystrdup (p);
            if (!item->name)
                ctx->out_of_core = 1;
            break;
        }
    }

    if (field)
        ctx->key_cond = 1;
}



GpgmeError
gpgme_op_trustlist_start ( GpgmeCtx c, const char *pattern, int max_level )
{
    GpgmeError rc = 0;

    fail_on_pending_request( c );
    if ( !pattern || !*pattern ) {
        return mk_error (Invalid_Value);
    }

    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;

    if ( c->gpg ) {
        _gpgme_gpg_release ( c->gpg ); 
        c->gpg = NULL;
    }
    
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, trustlist_status_handler, c );
    rc = _gpgme_gpg_set_colon_line_handler ( c->gpg,
                                             trustlist_colon_handler, c );
    if (rc)
        goto leave;

    /* build the commandline */
    _gpgme_gpg_add_arg ( c->gpg, "--with-colons" );
    _gpgme_gpg_add_arg ( c->gpg, "--list-trust-path" );
    
    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    _gpgme_gpg_add_arg ( c->gpg, pattern );

    /* and kick off the process */
    rc = _gpgme_gpg_spawn ( c->gpg, c );

 leave:
    if (rc) {
        c->pending = 0; 
        _gpgme_gpg_release ( c->gpg ); c->gpg = NULL;
    }
    return rc;
}


GpgmeError
gpgme_op_trustlist_next ( GpgmeCtx c, GpgmeTrustItem *r_item )
{
    struct trust_queue_item_s *q;

    if (!r_item)
        return mk_error (Invalid_Value);
    *r_item = NULL;
    if (!c)
        return mk_error (Invalid_Value);
    if ( !c->pending )
        return mk_error (No_Request);
    if ( c->out_of_core )
        return mk_error (Out_Of_Core);

    if ( !c->trust_queue ) {
        _gpgme_wait_on_condition (c, 1, &c->key_cond );
        if ( c->out_of_core )
            return mk_error (Out_Of_Core);
        if ( !c->key_cond )
            return mk_error (EOF);
        c->key_cond = 0; 
        assert ( c->trust_queue );
    }
    q = c->trust_queue;
    c->trust_queue = q->next;

    *r_item = q->item;
    xfree (q);
    return 0;
}


void
gpgme_trust_item_release ( GpgmeTrustItem item )
{
    if (!item)
        return;
    xfree (item->name);
    xfree (item);
}


const char *
gpgme_trust_item_get_string_attr ( GpgmeTrustItem item, GpgmeAttr what,
                                   const void *reserved, int idx )
{
    const char *val = NULL;

    if (!item)
        return NULL;
    if (reserved)
        return NULL;
    if (idx)
        return NULL;

    switch (what) {
      case GPGME_ATTR_KEYID:
        val = item->keyid;
        break;
      case GPGME_ATTR_OTRUST:  
        val = item->ot;
        break;
      case GPGME_ATTR_VALIDITY:
        val = item->val;
        break;
      case GPGME_ATTR_USERID:  
        val = item->name;
        break;
      default:
        break;
    }
    return val;
}


int
gpgme_trust_item_get_int_attr ( GpgmeTrustItem item, GpgmeAttr what,
                                const void *reserved, int idx )
{
    int val = 0;

    if (!item)
        return 0;
    if (reserved)
        return 0;
    if (idx)
        return 0;

    switch (what) {
      case GPGME_ATTR_LEVEL:    
        val = item->level;
        break;
      case GPGME_ATTR_TYPE:    
        val = item->type;
        break;
      default:
        break;
    }
    return val;
}


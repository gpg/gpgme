/* keylist.c -  key listing
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
#include "key.h"

#define my_isdigit(a) ( (a) >='0' && (a) <= '9' )

static void finish_key ( GpgmeCtx ctx );


static void
keylist_status_handler ( GpgmeCtx ctx, GpgStatusCode code, char *args )
{
    if ( ctx->out_of_core )
        return;

    switch (code) {
      case STATUS_EOF:
        if (ctx->tmp_key)
            finish_key (ctx);
        break;

      default:
        /* ignore all other codes */
        break;
    }
}


static time_t
parse_timestamp ( char *p )
{
    struct tm tm;
    int i;
    
    if (!*p )
        return 0;

    if (strlen(p) < 10 || p[4] != '-' || p[7] != '-' )
        return (time_t)-1;
    p[4] = 0;
    p[7] = 0;
    p[10] = 0; /* just in case the time part follows */
    memset (&tm, 0, sizeof tm);

    i = atoi (p);
    if ( i < 1900 )
        return (time_t)-1;
    tm.tm_year = i - 1900;

    i = atoi (p+5);
    if ( i < 1 || i > 12 )
        return (time_t)-1;
    tm.tm_mon = i-1;

    i = atoi (p+8);
    if ( i < 1 || i > 31 )
        return (time_t)-1;
    tm.tm_mday = i;

    return mktime (&tm);
}


static void
set_mainkey_trust_info ( GpgmeKey key, const char *s )
{
    /* look at letters and stop at the first digit */
    for (; *s && !my_isdigit (*s); s++ ) {
        switch (*s) {
          case 'e': key->keys.flags.expired = 1; break;
          case 'r': key->keys.flags.revoked = 1; break;
          case 'd': key->keys.flags.disabled = 1; break;
          case 'n': key->uids->validity = 1; break;
          case 'm': key->uids->validity = 2; break;
          case 'f': key->uids->validity = 3; break;
          case 'u': key->uids->validity = 4; break;
        }
    }
}

static void
set_subkey_trust_info ( struct subkey_s *k, const char *s )
{
    /* look at letters and stop at the first digit */
    for (; *s && !my_isdigit (*s); s++ ) {
        switch (*s) {
          case 'e': k->flags.expired = 1; break;
          case 'r': k->flags.revoked = 1; break;
          case 'd': k->flags.disabled = 1; break;
        }
    }
}


/* Note: we are allowed to modify line */
static void
keylist_colon_handler ( GpgmeCtx ctx, char *line )
{
    char *p, *pend;
    int field = 0;
    enum {
        RT_NONE, RT_SIG, RT_UID, RT_SUB, RT_PUB, RT_FPR, RT_SSB, RT_SEC
    } rectype = RT_NONE;
    GpgmeKey key = ctx->tmp_key;
    int i;
    const char *trust_info = NULL;
    struct subkey_s *sk = NULL;

    if ( ctx->out_of_core )
        return;
    if (!line)
        return; /* EOF */

    for (p = line; p; p = pend) {
        field++;
        pend = strchr (p, ':');
        if (pend) 
            *pend++ = 0;

        if ( field == 1 ) {
            if ( !strcmp ( p, "sig" ) )
                rectype = RT_SIG;
            else if ( !strcmp ( p, "uid" ) && key ) {
                rectype = RT_UID;
                key = ctx->tmp_key;
            }
            else if ( !strcmp (p, "sub") && key ) {
                /* start a new subkey */
                rectype = RT_SUB;
                if ( !(sk = _gpgme_key_add_subkey (key)) ) {
                    ctx->out_of_core=1;
                    return;
                }
            }
            else if ( !strcmp (p, "ssb") && key ) {
                /* start a new secret subkey */
                rectype = RT_SSB;
                if ( !(sk = _gpgme_key_add_secret_subkey (key)) ) {
                    ctx->out_of_core=1;
                    return;
                }
            }
            else if ( !strcmp (p, "pub") ) {
                /* start a new keyblock */
                if ( _gpgme_key_new ( &key ) ) {
                    ctx->out_of_core=1; /* the only kind of error we can get*/
                    return;
                }
                rectype = RT_PUB;
                if ( ctx->tmp_key )
                    finish_key ( ctx );
                assert ( !ctx->tmp_key );
                ctx->tmp_key = key;
            }
            else if ( !strcmp (p, "sec") ) {
                /* start a new keyblock */
                if ( _gpgme_key_new_secret ( &key ) ) {
                    ctx->out_of_core=1; /*the only kind of error we can get*/
                    return;
                }
                rectype = RT_SEC;
                if ( ctx->tmp_key )
                    finish_key ( ctx );
                assert ( !ctx->tmp_key );
                ctx->tmp_key = key;
            }
            else if ( !strcmp ( p, "fpr" ) && key ) 
                rectype = RT_FPR;
            else 
                rectype = RT_NONE;
            
        }
        else if ( rectype == RT_PUB || rectype == RT_SEC ) {
            switch (field) {
              case 2: /* trust info */
                trust_info = p;  /*save for later */
                break;
              case 3: /* key length */
                i = atoi (p); 
                if ( i > 1 ) /* ignore invalid values */
                    key->keys.key_len = i; 
                break;
              case 4: /* pubkey algo */
                i = atoi (p);
                if ( i > 1 && i < 128 )
                    key->keys.key_algo = i;
                break;
              case 5: /* long keyid */
                if ( strlen (p) == DIM(key->keys.keyid)-1 )
                    strcpy (key->keys.keyid, p);
                break;
              case 6: /* timestamp (1998-02-28) */
                key->keys.timestamp = parse_timestamp (p);
                break;
              case 7: /* valid for n days */
                break;
              case 8: /* reserved (LID) */
                break;
              case 9: /* ownertrust */
                break;
              case 10: /* This is the first name listed */
                if ( _gpgme_key_append_name ( key, p) )
                    ctx->out_of_core = 1;
                else {
                    if (trust_info)
                        set_mainkey_trust_info (key, trust_info);
                }
                break;
              case 11:  /* signature class  */
                break;
              case 12:
                pend = NULL;  /* we can stop here */
                break;
            }
        }
        else if ( (rectype == RT_SUB || rectype== RT_SSB) && sk ) {
            switch (field) {
              case 2: /* trust info */
                set_subkey_trust_info ( sk, p);
                break;
              case 3: /* key length */
                i = atoi (p); 
                if ( i > 1 ) /* ignore invalid values */
                    sk->key_len = i; 
                break;
              case 4: /* pubkey algo */
                i = atoi (p);
                if ( i > 1 && i < 128 )
                    sk->key_algo = i;
                break;
              case 5: /* long keyid */
                if ( strlen (p) == DIM(sk->keyid)-1 )
                    strcpy (sk->keyid, p);
                break;
              case 6: /* timestamp (1998-02-28) */
                sk->timestamp = parse_timestamp (p);
                break;
              case 7: /* valid for n days */
                break;
              case 8: /* reserved (LID) */
                break;
              case 9: /* ownertrust */
                break;
              case 10:/* user ID n/a for a subkey */
                break;
              case 11:  /* signature class  */
                break;
              case 12:
                pend = NULL;  /* we can stop here */
                break;
            }
        }
        else if ( rectype == RT_UID ) {
            switch (field) {
              case 2: /* trust info */
                trust_info = p;  /*save for later */
                break;
              case 10: /* the 2nd, 3rd,... user ID */
                if ( _gpgme_key_append_name ( key, p) )
                    ctx->out_of_core = 1;
                else {
                    if (trust_info)
                        set_mainkey_trust_info (key, trust_info);
                }
                pend = NULL;  /* we can stop here */
                break;
            }
        }
        else if ( rectype == RT_FPR ) {
            switch (field) {
              case 10: /* fingerprint (take only the first one)*/
                if ( !key->keys.fingerprint && *p ) {
                    key->keys.fingerprint = xtrystrdup (p);
                    if ( !key->keys.fingerprint )
                        ctx->out_of_core = 1;
                }
                pend = NULL; /* that is all we want */
                break;
            }
        }
    }
    
}


/*
 * We have read an entire key into ctx->tmp_key and should now finish
 * it.  It is assumed that this releases ctx->tmp_key.
 */
static void
finish_key ( GpgmeCtx ctx )
{
    GpgmeKey key = ctx->tmp_key;
    struct key_queue_item_s *q, *q2;
    
    assert (key);
    ctx->tmp_key = NULL;
    
    q = xtrymalloc ( sizeof *q );
    if ( !q ) {
        gpgme_key_release (key);
        ctx->out_of_core = 1;
        return;
    }
    q->key = key;
    q->next = NULL;
    /* fixme: lock queue. Use a tail pointer? */
    if ( !(q2 = ctx->key_queue) )
        ctx->key_queue = q;
    else {
        for ( ; q2->next; q2 = q2->next )
            ;
        q2->next = q;
    }
    ctx->key_cond = 1;
    /* fixme: unlock queue */
}




GpgmeError
gpgme_op_keylist_start ( GpgmeCtx c,  const char *pattern, int secret_only )
{
    GpgmeError rc = 0;
    int i;

    fail_on_pending_request( c );
    c->pending = 1;

    _gpgme_release_result (c);
    c->out_of_core = 0;

    if ( c->gpg ) {
        _gpgme_gpg_release ( c->gpg ); 
        c->gpg = NULL;
    }
    gpgme_key_release (c->tmp_key);
    c->tmp_key = NULL;
    /* Fixme: release key_queue */
    
    rc = _gpgme_gpg_new ( &c->gpg );
    if (rc)
        goto leave;

    _gpgme_gpg_set_status_handler ( c->gpg, keylist_status_handler, c );

    rc = _gpgme_gpg_set_colon_line_handler ( c->gpg,
                                             keylist_colon_handler, c );
    if (rc)
        goto leave;

    /* build the commandline */
    for ( i=0; i < c->verbosity; i++ )
        _gpgme_gpg_add_arg ( c->gpg, "--verbose" );
    _gpgme_gpg_add_arg ( c->gpg, "--with-colons" );
    _gpgme_gpg_add_arg ( c->gpg, "--with-fingerprint" );
    if (c->keylist_mode == 1)
        _gpgme_gpg_add_arg ( c->gpg, "--no-expensive-trust-checks" );
    _gpgme_gpg_add_arg ( c->gpg, secret_only?
                         "--list-secret-keys":"--list-keys" );
    
    /* Tell the gpg object about the data */
    _gpgme_gpg_add_arg ( c->gpg, "--" );
    if (pattern && *pattern)
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
gpgme_op_keylist_next ( GpgmeCtx c, GpgmeKey *r_key )
{
    struct key_queue_item_s *q;

    if (!r_key)
        return mk_error (Invalid_Value);
    *r_key = NULL;
    if (!c)
        return mk_error (Invalid_Value);
    if ( !c->pending )
        return mk_error (No_Request);
    if ( c->out_of_core )
        return mk_error (Out_Of_Core);

    if ( !c->key_queue ) {
        _gpgme_wait_on_condition (c, 1, &c->key_cond );
        if ( c->out_of_core )
            return mk_error (Out_Of_Core);
        if ( !c->key_cond )
            return mk_error (EOF);
        c->key_cond = 0; 
        assert ( c->key_queue );
    }
    q = c->key_queue;
    c->key_queue = q->next;

    *r_key = q->key;
    xfree (q);
    return 0;
}





/* recipient.c - mainatin recipient sets
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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
#include <assert.h>

#include "util.h"
#include "context.h"
#include "rungpg.h"

GpgmeError
gpgme_recipients_new (GpgmeRecipients *r_rset)
{
    GpgmeRecipients rset;

    rset = xtrycalloc ( 1, sizeof *rset  );
    if (!rset)
        return mk_error (Out_Of_Core);
    *r_rset = rset;
    return 0;
}

void
gpgme_recipients_release ( GpgmeRecipients rset )
{
    /* fixme: release the linked list */
    xfree ( rset );
}


GpgmeError
gpgme_recipients_add_name (GpgmeRecipients rset, const char *name )
{
    return gpgme_recipients_add_name_with_validity (
        rset, name, GPGME_VALIDITY_UNKNOWN
        );
}

GpgmeError
gpgme_recipients_add_name_with_validity (GpgmeRecipients rset,
                                         const char *name,
                                         GpgmeValidity val )
{
    struct user_id_s *r;

    if (!name || !rset )
        return mk_error (Invalid_Value);
    r = xtrymalloc ( sizeof *r + strlen (name) );
    if (!r)
        return mk_error (Out_Of_Core);
    r->validity = val;
    r->name_part = "";
    r->email_part = "";
    r->comment_part = "";
    strcpy (r->name, name );
    r->next = rset->list;
    rset->list = r;
    return 0;
}



unsigned int 
gpgme_recipients_count ( const GpgmeRecipients rset )
{
    struct user_id_s *r;
    unsigned int count = 0;
    
    if ( rset ) {
        for (r=rset->list ; r; r = r->next )
            count++;
    }
    return count;
}



GpgmeError
gpgme_recipients_enum_open ( const GpgmeRecipients rset, void **ctx )
{
    if (!rset || !ctx)
        return mk_error (Invalid_Value);

    *ctx = rset->list;
    return 0;
}

const char *
gpgme_recipients_enum_read ( const GpgmeRecipients rset, void **ctx )
{
    struct user_id_s *r;

    if (!rset || !ctx)
        return NULL; /* oops */
    
    r = *ctx;
    if ( r ) {
        const char *s = r->name;
        r = r->next;
        *ctx = r;
        return s;
    }

    return NULL;
}

GpgmeError
gpgme_recipients_enum_close ( const GpgmeRecipients rset, void **ctx )
{
    if (!rset || !ctx)
        return mk_error (Invalid_Value);
    *ctx = NULL;
    return 0;
}


void
_gpgme_append_gpg_args_from_recipients (
    const GpgmeRecipients rset,
    GpgObject gpg )
{
    struct user_id_s *r;

    assert (rset);
    for (r=rset->list ; r; r = r->next ) {
        _gpgme_gpg_add_arg ( gpg, "-r" );
        _gpgme_gpg_add_arg ( gpg, r->name );
    }    
}

int
_gpgme_recipients_all_valid ( const GpgmeRecipients rset )
{
    struct user_id_s *r;

    assert (rset);
    for (r=rset->list ; r; r = r->next ) {
        if (r->validity != GPGME_VALIDITY_FULL
            && r->validity != GPGME_VALIDITY_ULTIMATE )
            return 0; /*no*/
    }
    return 1; /*yes*/
}




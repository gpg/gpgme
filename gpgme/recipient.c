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
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "rungpg.h"

/**
 * gpgme_recipients_new:
 * @r_rset: Returns the new object.
 * 
 * Create a new uninitialized Reciepient set Object.
 * 
 * Return value: 0 on success or an error code.
 **/
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

/**
 * gpgme_recipients_release:
 * @rset: Recipient Set object
 * 
 * Free the given object.
 **/
void
gpgme_recipients_release ( GpgmeRecipients rset )
{
    if (rset) {
        struct user_id_s *u, *u2;

        for (u = rset->list; u; u = u2) {
            u2 = u->next;
            xfree(u);
        }
    }
    xfree ( rset );
}


/**
 * gpgme_recipients_add_name:
 * @rset: Recipient Set object 
 * @name: user name or keyID
 * 
 * Add a name to the recipient Set.
 * 
 * Return value: 0 on success or an error code
 **/
GpgmeError
gpgme_recipients_add_name (GpgmeRecipients rset, const char *name )
{
    return gpgme_recipients_add_name_with_validity (
        rset, name, GPGME_VALIDITY_UNKNOWN
        );
}

/**
 * gpgme_recipients_add_name_with_validity:
 * @rset: Recipient Set object
 * @name: user name or keyID
 * @val: Validity value 
 * 
 * Same as gpgme_recipients_add_name() but with explictly given key
 * validity.  Use one of the constants 
 * %GPGME_VALIDITY_UNKNOWN, %GPGME_VALIDITY_UNDEFINED,
 * %GPGME_VALIDITY_NEVER, %GPGME_VALIDITY_MARGINAL,
 * %GPGME_VALIDITY_FULL, %GPGME_VALIDITY_ULTIMATE5
 * for the validity.  %GPGME_VALIDITY_UNKNOWN is implicitly used by
 * gpgme_recipients_add_name().
 *
 * Return value: o on success or an error value.
 **/
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



/**
 * gpgme_recipients_count:
 * @rset: Recipient Set object
 * 
 * Return value: The number of recipients in the set.
 **/
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



/**
 * gpgme_recipients_enum_open:
 * @rset: Recipient Set object
 * @ctx: Enumerator
 * 
 * Start an enumeration on the Recipient Set object.  The caller must pass 
 * the address of a void pointer which is used as the enumerator object.
 * 
 * Return value: 0 on success or an error code.
 *
 * See also: gpgme_recipients_enum_read(), gpgme_recipients_enum_close().
 **/
GpgmeError
gpgme_recipients_enum_open ( const GpgmeRecipients rset, void **ctx )
{
    if (!rset || !ctx)
        return mk_error (Invalid_Value);

    *ctx = rset->list;
    return 0;
}

/**
 * gpgme_recipients_enum_read:
 * @rset: Recipient Set object
 * @ctx: Enumerator 
 * 
 * Return the name of the next user name from the given recipient
 * set. This name is valid as along as the @rset is valid and until
 * the next call to this function.
 * 
 * Return value: name or NULL for no more names.
 *
 * See also: gpgme_recipients_enum_read(), gpgme_recipients_enum_close().
 **/
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

/**
 * gpgme_recipients_enum_close:
 * @rset: Recipient Set object
 * @ctx: Enumerator
 * 
 * Release the enumerator @rset for this object.
 * 
 * Return value: 0 on success or %GPGME_Invalid_Value;
 *
 * See also: gpgme_recipients_enum_read(), gpgme_recipients_enum_close().
 **/
GpgmeError
gpgme_recipients_enum_close ( const GpgmeRecipients rset, void **ctx )
{
    if (!rset || !ctx)
        return mk_error (Invalid_Value);
    *ctx = NULL;
    return 0;
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




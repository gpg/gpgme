/* recipient.c - mainatin recipient sets
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
#include <assert.h>

#include "util.h"
#include "context.h"
#include "rungpg.h"

GpgmeError
gpgme_new_recipient_set (GpgmeRecipientSet *r_rset)
{
    GpgmeRecipientSet rset;

    rset = xtrycalloc ( 1, sizeof *rset  );
    if (!rset)
        return mk_error (Out_Of_Core);
    *r_rset = rset;
    return 0;
}

void
gpgme_release_recipient_set ( GpgmeRecipientSet rset )
{
    /* fixme: release the linked list */
    xfree ( rset );
}


GpgmeError
gpgme_add_recipient (GpgmeRecipientSet rset, const char *name )
{
    struct recipient_s *r;

    if (!name || !rset )
        return mk_error (Invalid_Value);
    r = xtrymalloc ( sizeof *r + strlen (name) );
    if (!r)
        return mk_error (Out_Of_Core);
    strcpy (r->name, name );
    r->next = rset->list;
    rset->list = r;
    return 0;
}

unsigned int 
gpgme_count_recipients ( const GpgmeRecipientSet rset )
{
    struct recipient_s *r;
    unsigned int count = 0;
    
    if ( rset ) {
        for (r=rset->list ; r; r = r->next )
            count++;
    }
    return count;
}


void
_gpgme_append_gpg_args_from_recipients (
    const GpgmeRecipientSet rset,
    GpgObject gpg )
{
    struct recipient_s *r;

    assert (rset);
    for (r=rset->list ; r; r = r->next ) {
        _gpgme_gpg_add_arg ( gpg, "-r" );
        _gpgme_gpg_add_arg ( gpg, r->name );
    }    
}








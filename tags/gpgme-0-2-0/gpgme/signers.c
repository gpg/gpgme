/* signers.c - maintain signer sets
 *	Copyright (C) 2001 Werner Koch (dd9jn)
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

/* The signers are directly stored in the context.
 * So this is quite different to a recipient set.
 */


void
gpgme_signers_clear (GpgmeCtx c)
{
    int i;

    return_if_fail (c);

    if (!c->signers)
        return;
    for (i=0; i < c->signers_size; i++ ) {
        if (!c->signers[i])
            break;
        gpgme_key_unref (c->signers[i]);
        c->signers[i] = NULL;
    }
}


GpgmeError
gpgme_signers_add (GpgmeCtx c, const GpgmeKey key)
{
    int i = 0;

    if (!c || !key)
        return mk_error (Invalid_Value);

    if (!c->signers)
        c->signers_size = 0;

    for (i=0; i < c->signers_size && c->signers[i]; i++ )
        ;
    if ( !(i < c->signers_size) ) {
        GpgmeKey *newarr;
        int j;
        int n = c->signers_size + 5;

        newarr = xtrycalloc ( n, sizeof *newarr );
        if ( !newarr )
            return mk_error (Out_Of_Core);
        for (j=0; j < c->signers_size; j++ )
            newarr[j] = c->signers[j];
        c->signers_size = n;
        xfree (c->signers);
        c->signers = newarr;
    }
    gpgme_key_ref (key);
    c->signers[i] = key;
    return 0;
}


GpgmeKey
gpgme_signers_enum (const GpgmeCtx c, int seq )
{
    int i;

    return_null_if_fail (c);
    return_null_if_fail (seq>=0);

    if (!c->signers)
        c->signers_size = 0;
    for (i=0; i < c->signers_size && c->signers[i]; i++ ) {
        if (i==seq) {
            gpgme_key_ref (c->signers[i]);
            return c->signers[i];
        }
    }
    return NULL;
}





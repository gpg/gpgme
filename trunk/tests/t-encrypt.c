/* t-encrypt.c  - regression test
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../gpgme/gpgme.h"

#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)


int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    GpgmeData in, out;
    GpgmeRecipientSet rset;

    err = gpgme_new_context (&ctx);
    fail_if_err (err);

    err = gpgme_new_data ( &in, "Hallo Leute", 11, 0 );
    fail_if_err (err);

    err = gpgme_new_data ( &out, NULL, 0,0 );
    fail_if_err (err);

    err = gpgme_new_recipient_set (&rset);
    fail_if_err (err);
    err = gpgme_add_recipient (rset, "Bob");
    fail_if_err (err);


    err = gpgme_encrypt (ctx, rset, in, out );
    fail_if_err (err);

   
    gpgme_release_recipient_set (rset);
    gpgme_release_data (in);
    gpgme_release_data (out);
    gpgme_release_context (ctx);
    return 0;
}



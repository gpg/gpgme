/* t-verify.c  - regression test
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

static const char test_text1[] = "Just GNU it!\n";
static const char test_text1f[]= "Just GNU it?\n";
static const char test_sig1[] =
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iEYEABECAAYFAjoKgjIACgkQLXJ8x2hpdzQMSwCeO/xUrhysZ7zJKPf/FyXA//u1\n"
"ZgIAn0204PBR7yxSdQx6CFxugstNqmRv\n"
"=yku6\n"
"-----END PGP SIGNATURE-----\n"
;


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
    GpgmeData sig, text;

    err = gpgme_new (&ctx);
    fail_if_err (err);

  do {
    err = gpgme_data_new ( &text, test_text1, strlen (test_text1), 0 );
    fail_if_err (err);
    err = gpgme_data_new ( &sig, test_sig1, strlen (test_sig1), 0 );
    fail_if_err (err);

    puts ("checking a valid message:\n");
    err = gpgme_op_verify (ctx, sig, text );
    fail_if_err (err);

    puts ("checking a manipulated message:\n");
    gpgme_data_release (text);
    err = gpgme_data_new ( &text, test_text1f, strlen (test_text1f), 0 );
    fail_if_err (err);
    gpgme_data_rewind ( sig );
    err = gpgme_op_verify (ctx, sig, text );
    fail_if_err (err);

    gpgme_data_release (sig);
    gpgme_data_release (text);
 
} while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
      gpgme_release (ctx);
    
    return 0;
}




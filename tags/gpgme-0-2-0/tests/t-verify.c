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
#if 0
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iEYEABECAAYFAjoKgjIACgkQLXJ8x2hpdzQMSwCeO/xUrhysZ7zJKPf/FyXA//u1\n"
"ZgIAn0204PBR7yxSdQx6CFxugstNqmRv\n"
"=yku6\n"
"-----END PGP SIGNATURE-----\n"
#elif 0
"-----BEGIN PGP SIGNATURE-----\n"
"Version: GnuPG v1.0.4-2 (GNU/Linux)\n"
"Comment: For info see http://www.gnupg.org\n"
"\n"
"iJcEABECAFcFAjoS8/E1FIAAAAAACAAkZm9vYmFyLjF0aGlzIGlzIGEgbm90YXRp\n"
"b24gZGF0YSB3aXRoIDIgbGluZXMaGmh0dHA6Ly93d3cuZ3Uub3JnL3BvbGljeS8A\n"
"CgkQLXJ8x2hpdzQLyQCbBW/fgU8ZeWSlWPM1F8umHX17bAAAoIfSNDSp5zM85XcG\n"
"iwxMrf+u8v4r\n"
"=88Zo\n"
"-----END PGP SIGNATURE-----\n"
#elif 1
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt\n"
"bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv\n"
"b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw\n"
"Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc\n"
"dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==\n"
"=nts1\n"
"-----END PGP SIGNATURE-----\n"
#endif
;



#define fail_if_err(a) do { if(a) {                                       \
                               fprintf (stderr, "%s:%d: GpgmeError %s\n", \
                                __FILE__, __LINE__, gpgme_strerror(a));   \
                                exit (1); }                               \
                             } while(0)


static const char *
status_string (GpgmeSigStat status)
{
    const char *s = "?";

    switch ( status ) {
      case GPGME_SIG_STAT_NONE:
        s = "None";
        break;
      case GPGME_SIG_STAT_NOSIG:
        s = "No Signature";
        break;
      case GPGME_SIG_STAT_GOOD:
        s = "Good";
        break;
      case GPGME_SIG_STAT_BAD:
        s = "Bad";
        break;
      case GPGME_SIG_STAT_NOKEY:
        s = "No Key";
        break;
      case GPGME_SIG_STAT_ERROR:
        s = "Error";
        break;
      case GPGME_SIG_STAT_DIFF:
        s = "More than one signature";
        break;
    }
    return s;
}


static void
print_sig_stat ( GpgmeCtx ctx, GpgmeSigStat status )
{
    const char *s;
    time_t created;
    int idx;
    GpgmeKey key;

    printf ("Verification Status: %s\n", status_string (status));
    
    for(idx=0; (s=gpgme_get_sig_status (ctx, idx, &status, &created)); idx++ ) {
        printf ("sig %d: created: %lu status: %s\n", idx, (unsigned long)created,
                status_string(status) );
        printf ("sig %d: fpr/keyid=`%s'\n", idx, s );
        if ( !gpgme_get_sig_key (ctx, idx, &key) ) {
            char *p = gpgme_key_get_as_xml ( key );
            printf ("sig %d: key object:\n%s\n", idx, p );
            free (p);
            gpgme_key_release (key);
        }
    }
}

int 
main (int argc, char **argv )
{
    GpgmeCtx ctx;
    GpgmeError err;
    GpgmeData sig, text;
    GpgmeSigStat status;
    char *nota;

    err = gpgme_new (&ctx);
    fail_if_err (err);

  do {
    err = gpgme_data_new_from_mem ( &text,
                                    test_text1, strlen (test_text1), 0 );
    fail_if_err (err);
  #if 1
    err = gpgme_data_new_from_mem ( &sig,
                                    test_sig1, strlen (test_sig1), 0 );
  #else
    err = gpgme_data_new_from_file ( &sig, "xx1", 1 );
  #endif
    fail_if_err (err);

    puts ("checking a valid message:\n");
    err = gpgme_op_verify (ctx, sig, text, &status );
    print_sig_stat ( ctx, status );
    print_sig_stat ( ctx, status );
    print_sig_stat ( ctx, status );
    print_sig_stat ( ctx, status );
    fail_if_err (err);

    if ( (nota=gpgme_get_notation (ctx)) )
        printf ("---Begin Notation---\n%s---End Notation---\n", nota );

    puts ("checking a manipulated message:\n");
    gpgme_data_release (text);
    err = gpgme_data_new_from_mem ( &text,
                                    test_text1f, strlen (test_text1f), 0 );
    fail_if_err (err);
    gpgme_data_rewind ( sig );
    err = gpgme_op_verify (ctx, sig, text, &status );
    print_sig_stat ( ctx, status );
    fail_if_err (err);
    if ( (nota=gpgme_get_notation (ctx)) )
        printf ("---Begin Notation---\n%s---End Notation---\n", nota );

    gpgme_data_release (sig);
    gpgme_data_release (text);
 
} while ( argc > 1 && !strcmp( argv[1], "--loop" ) );
      gpgme_release (ctx);
    
    return 0;
}




/* t-verify.c  - regression test
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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

#include <gpgme.h>

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
static const char test_sig2[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n"
"GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n"
"y1kvP4y+8D5a11ang0udywsA\n"
"=Crq6\n"
"-----END PGP MESSAGE-----\n";


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
      case GPGME_SIG_STAT_GOOD_EXP:
        s = "Good but expired";
        break;
      case GPGME_SIG_STAT_GOOD_EXPKEY:
        s = "Good but key exipired";
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

static const char *
validity_string (GpgmeValidity val)
{
  const char *s = "?";

  switch (val)
    {
    case GPGME_VALIDITY_UNKNOWN: s = "unknown"; break;
    case GPGME_VALIDITY_NEVER:   s = "not trusted"; break;
    case GPGME_VALIDITY_MARGINAL:s = "marginal trusted"; break;
    case GPGME_VALIDITY_FULL:   s = "fully trusted"; break;
    case GPGME_VALIDITY_UNDEFINED:
    case GPGME_VALIDITY_ULTIMATE:
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
        printf ("sig %d: created: %lu expires: %lu status: %s\n",
                idx, (unsigned long)created, 
                gpgme_get_sig_ulong_attr (ctx, idx, GPGME_ATTR_EXPIRE, 0),
                status_string(status) );
        printf ("sig %d: fpr/keyid: `%s' validity: %s\n",
                idx, s,
                validity_string (gpgme_get_sig_ulong_attr
                                 (ctx, idx, GPGME_ATTR_VALIDITY, 0)) );
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
    int n = 0;
    size_t len;
    int j;

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
    fail_if_err (err);
    print_sig_stat ( ctx, status );
    if (status != GPGME_SIG_STAT_GOOD)
      {
	fprintf (stderr, "%s:%d: Wrong sig stat\n", __FILE__, __LINE__);
	exit (1);
      }

    if ( (nota=gpgme_get_notation (ctx)) )
        printf ("---Begin Notation---\n%s---End Notation---\n", nota );

    puts ("checking a manipulated message:\n");
    gpgme_data_release (text);
    err = gpgme_data_new_from_mem ( &text,
                                    test_text1f, strlen (test_text1f), 0 );
    fail_if_err (err);
    gpgme_data_rewind ( sig );
    err = gpgme_op_verify (ctx, sig, text, &status );
    fail_if_err (err);

    print_sig_stat (ctx, status);
    if (status != GPGME_SIG_STAT_BAD)
      {
	fprintf (stderr, "%s:%d: Wrong sig stat\n", __FILE__, __LINE__);
	exit (1);
      }
    if ( (nota=gpgme_get_notation (ctx)) )
        printf ("---Begin Notation---\n%s---End Notation---\n", nota );

    puts ("checking a normal signature:");
    gpgme_data_release (sig);
    gpgme_data_release (text);
    err = gpgme_data_new_from_mem (&sig,  test_sig2, strlen (test_sig2), 0);
    fail_if_err (err);
    err = gpgme_data_new (&text);
    fail_if_err (err);
    err = gpgme_op_verify (ctx, sig, text, &status);
    fail_if_err (err);

    nota = gpgme_data_release_and_get_mem (text, &len);
    for (j = 0; j < len; j++)
      putchar (nota[j]);
    if (strncmp (nota, test_text1, strlen (test_text1)))
      {
	fprintf (stderr, "%s:%d: Wrong plaintext\n", __FILE__, __LINE__);
	exit (1);
      }
   
    print_sig_stat (ctx, status);
    if (status != GPGME_SIG_STAT_GOOD)
      {
	fprintf (stderr, "%s:%d: Wrong sig stat\n", __FILE__, __LINE__);
	exit (1);
      }

    if ((nota = gpgme_get_notation (ctx)))
      printf ("---Begin Notation---\n%s---End Notation---\n", nota);

    gpgme_data_release (sig);
 
} while ( argc > 1 && !strcmp( argv[1], "--loop" ) && ++n < 20 );
      gpgme_release (ctx);
    
    return 0;
}

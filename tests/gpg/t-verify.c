/* t-verify.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#include "t-support.h"


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

/* A message with a prepended but unsigned plaintext packet. */
static const char double_plaintext_sig[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"rDRiCmZvb2Jhci50eHRF4pxNVGhpcyBpcyBteSBzbmVha3kgcGxhaW50ZXh0IG1l\n"
"c3NhZ2UKowGbwMvMwCSoW1RzPCOz3IRxTWISa6JebnG666MFD1wzSzJSixQ81XMV\n"
"UlITUxTyixRyKxXKE0uSMxQyEosVikvyCwpSU/S4FNCArq6Ce1F+aXJGvoJvYlGF\n"
"erFCTmJxiUJ5flFKMVeHGwuDIBMDGysTyA4GLk4BmO036xgWzMgzt9V85jCtfDFn\n"
"UqVooWlGXHwNw/xg/fVzt9VNbtjtJ/fhUqYo0/LyCGEA\n"
"=6+AK\n"
"-----END PGP MESSAGE-----\n";




static void
check_result (gpgme_verify_result_t result, unsigned int summary,
              const char *fpr,
	      gpgme_error_t status, int notation)
{
  gpgme_signature_t sig;

  sig = result->signatures;
  if (!sig || sig->next)
    {
      fprintf (stderr, "%s:%i: Unexpected number of signatures\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->summary != summary)
    {
      fprintf (stderr, "%s:%i: Unexpected signature summary: "
               "want=0x%x have=0x%x\n",
	       __FILE__, __LINE__, summary, sig->summary);
      exit (1);
    }
  if (strcmp (sig->fpr, fpr))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
	       __FILE__, __LINE__, sig->fpr);
      exit (1);
    }
  if (gpgme_err_code (sig->status) != status)
    {
      fprintf (stderr, "%s:%i: Unexpected signature status: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->status));
      exit (1);
    }
  if (notation)
    {
      static struct {
        const char *name;
        const char *value;
        int seen;
      } expected_notations[] = {
        { "bar",
	  "\xc3\xb6\xc3\xa4\xc3\xbc\xc3\x9f"
          " das waren Umlaute und jetzt ein prozent%-Zeichen" },
        { "foobar.1",
	  "this is a notation data with 2 lines" },
        { NULL,
	  "http://www.gu.org/policy/" }
      };
      int i;
      gpgme_sig_notation_t r;

      for (i=0; i < DIM(expected_notations); i++ )
        expected_notations[i].seen = 0;

      for (r = sig->notations; r; r = r->next)
        {
          int any = 0;
          for (i=0; i < DIM(expected_notations); i++)
            {
              if ( ((r->name && expected_notations[i].name
                     && !strcmp (r->name, expected_notations[i].name)
		     && r->name_len
		     == strlen (expected_notations[i].name))
                    || (!r->name && !expected_notations[i].name
			&& r->name_len == 0))
                   && r->value
                   && !strcmp (r->value, expected_notations[i].value)
		   && r->value_len == strlen (expected_notations[i].value))
                {
                  expected_notations[i].seen++;
                  any++;
                }
            }
          if (!any)
            {
              fprintf (stderr, "%s:%i: Unexpected notation data\n",
                       __FILE__, __LINE__);
              exit (1);
            }
        }
      for (i=0; i < DIM(expected_notations); i++ )
        {
          if (expected_notations[i].seen != 1)
            {
              fprintf (stderr, "%s:%i: Missing or duplicate notation data\n",
                       __FILE__, __LINE__);
              exit (1);
            }
        }
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i: Unexpectedly wrong key usage\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->validity != GPGME_VALIDITY_UNKNOWN)
    {
      fprintf (stderr, "%s:%i: Unexpected validity: %i\n",
	       __FILE__, __LINE__, sig->validity);
      exit (1);
    }
  if (gpgme_err_code (sig->validity_reason) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "%s:%i: Unexpected validity reason: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->validity_reason));
      exit (1);
    }
}


int
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t sig, text;
  gpgme_verify_result_t result;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  /* Checking a valid message.  */
  err = gpgme_data_new_from_mem (&text, test_text1, strlen (test_text1), 0);
  fail_if_err (err);
  err = gpgme_data_new_from_mem (&sig, test_sig1, strlen (test_sig1), 0);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, 0, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		GPG_ERR_NO_ERROR, 1);

  /* Checking a manipulated message.  */
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&text, test_text1f, strlen (test_text1f), 0);
  fail_if_err (err);
  gpgme_data_seek (sig, 0, SEEK_SET);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, GPGME_SIGSUM_RED, "2D727CC768697734",
		GPG_ERR_BAD_SIGNATURE, 0);

  /* Checking a normal signature.  */
  gpgme_data_release (sig);
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&sig, test_sig2, strlen (test_sig2), 0);
  fail_if_err (err);
  err = gpgme_data_new (&text);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, NULL, text);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, 0, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		GPG_ERR_NO_ERROR, 0);


  /* Checking an invalid message.  */
  gpgme_data_release (sig);
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&sig, double_plaintext_sig,
                                 strlen (double_plaintext_sig), 0);
  fail_if_err (err);
  err = gpgme_data_new (&text);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, NULL, text);
  if (gpgme_err_code (err) != GPG_ERR_BAD_DATA)
    {
      fprintf (stderr, "%s:%i: Double plaintext message not detected\n",
	       __FILE__, __LINE__);
      exit (1);
    }

  gpgme_data_release (sig);
  gpgme_data_release (text);
  gpgme_release (ctx);
  return 0;
}

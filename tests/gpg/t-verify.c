/* t-verify.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#define PGM "t-verify"
#include "t-support.h"



static const char test_text1[] = "Just GNU it!\n";
static const char test_text1f[]= "Just GNU it?\n";
static const char test_sig1[] =
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt\n"
"bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv\n"
"b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw\n"
"Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc\n"
"dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==\n"
"=nts1\n"
"-----END PGP SIGNATURE-----\n";

/* The same as test_sig1 but with a second signature for which we do
 * not have the public key (deleted after signature creation).  */
static const char test_sig1_plus_unknown_key[] =
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt\n"
"bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv\n"
"b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw\n"
"Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc\n"
"dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaIh1BAAWCAAdFiEENuwqcMZC\n"
"brD85btN+RyY8EnUIEwFAlrPR4cACgkQ+RyY8EnUIEyiuAEAm41LJTGUFDzhavRm\n"
"jNwqUZxGGOySduW+u/X1lEfV+MYA/2lJOo75rHtD1EG+tkFVWt4Ukj0rjhR132vZ\n"
"IOtrYAcG\n"
"=yYwZ\n"
"-----END PGP SIGNATURE-----\n";

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




/* NO_OF_SIGS is the expected number of signatures.  SKIP_SKIPS is
 * which of these signatures to check (0 based).  */
static void
check_result (gpgme_verify_result_t result, int no_of_sigs, int skip_sigs,
              unsigned int summary, const char *fpr,
	      gpgme_error_t status, int notation, int validity)
{
  gpgme_signature_t sig;
  int n;

  sig = result->signatures;
  for (n=0; sig; sig = sig->next)
    n++;
  if (n != no_of_sigs)
    {
      fprintf (stderr, "%s:%i: Unexpected number of signatures"
               " (got %d expected  %d)\n", PGM, __LINE__, n, no_of_sigs);
      exit (1);
    }
  if (skip_sigs >= n)
    {
      fprintf (stderr, "%s:%i: oops SKIPP_SIGS to high\n", PGM, __LINE__);
      exit (1);
    }

  for (n=0, sig = result->signatures; n < skip_sigs; sig = sig->next, n++)
    ;

  if (sig->summary != summary)
    {
      fprintf (stderr, "%s:%i:sig-%d: Unexpected signature summary: "
               "want=0x%x have=0x%x\n",
	       PGM, __LINE__, skip_sigs, summary, sig->summary);
      exit (1);
    }
  if (strcmp (sig->fpr, fpr))
    {
      if (strlen (sig->fpr) == 16 && strlen (fpr) == 40
          && !strncmp (sig->fpr, fpr + 24, 16))
        ; /* okay because gnupg < 2.2.6 only shows the keyid.  */
      else
        {
          fprintf (stderr, "%s:%i:sig-%d: Unexpected fingerprint: %s\n",
                   PGM, __LINE__, skip_sigs, sig->fpr);
          exit (1);
        }
    }
  if (gpgme_err_code (sig->status) != status)
    {
      fprintf (stderr, "%s:%i:sig-%d: Unexpected signature status: %s\n",
	       PGM, __LINE__, skip_sigs, gpgme_strerror (sig->status));
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
              fprintf (stderr, "%s:%i:sig-%d: Unexpected notation data\n",
                       PGM, __LINE__, skip_sigs);
              exit (1);
            }
        }
      for (i=0; i < DIM(expected_notations); i++ )
        {
          if (expected_notations[i].seen != 1)
            {
              fprintf (stderr, "%s:%i:sig-%d: "
                       "Missing or duplicate notation data\n",
                       PGM, __LINE__, skip_sigs);
              exit (1);
            }
        }
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i:sig-%d: Unexpectedly wrong key usage\n",
	       PGM, __LINE__, skip_sigs);
      exit (1);
    }
  if (sig->validity != validity)
    {
      fprintf (stderr, "%s:%i:sig-%d: Unexpected validity: "
               "want=%i have=%i\n",
	       PGM, __LINE__, skip_sigs, validity, sig->validity);
      exit (1);
    }
  if (gpgme_err_code (sig->validity_reason) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "%s:%i:sig-%d: Unexpected validity reason: %s\n",
	       PGM, __LINE__, skip_sigs,
               gpgme_strerror (sig->validity_reason));
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
  const char *s;

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
  check_result (result, 1, 0, GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN,
                "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		GPG_ERR_NO_ERROR, 1, GPGME_VALIDITY_FULL);

  /* Checking a manipulated message.  */
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&text, test_text1f, strlen (test_text1f), 0);
  fail_if_err (err);
  gpgme_data_seek (sig, 0, SEEK_SET);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, 1, 0, GPGME_SIGSUM_RED, "2D727CC768697734",
		GPG_ERR_BAD_SIGNATURE, 0, GPGME_VALIDITY_UNKNOWN);

  /* Checking a valid message.  But that one has a second signature
   * made by an unknown key.  */
  gpgme_data_release (text);
  gpgme_data_release (sig);
  err = gpgme_data_new_from_mem (&text, test_text1, strlen (test_text1), 0);
  fail_if_err (err);
  err = gpgme_data_new_from_mem (&sig, test_sig1_plus_unknown_key,
                                 strlen (test_sig1_plus_unknown_key), 0);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, 2, 0, GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN,
                "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		GPG_ERR_NO_ERROR, 1, GPGME_VALIDITY_FULL);
  check_result (result, 2, 1, GPGME_SIGSUM_KEY_MISSING,
                "36EC2A70C6426EB0FCE5BB4DF91C98F049D4204C",
		GPG_ERR_NO_PUBKEY, 0, GPGME_VALIDITY_UNKNOWN);


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
  check_result (result, 1, 0, GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN,
                "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		GPG_ERR_NO_ERROR, 0, GPGME_VALIDITY_FULL);


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
	       PGM, __LINE__);
      exit (1);
    }

  /* Checking that set/get_sernder works.  */
  err = gpgme_set_sender (ctx, "foo@example.org");
  fail_if_err (err);
  s = gpgme_get_sender (ctx);
  if (!s || strcmp (s, "foo@example.org"))
    {
      fprintf (stderr, "%s:%i: gpgme_{set,get}_sender mismatch\n",
               PGM, __LINE__);
      exit (1);
    }

  err = gpgme_set_sender (ctx, "<bar@example.org>");
  fail_if_err (err);
  s = gpgme_get_sender (ctx);
  if (!s || strcmp (s, "bar@example.org"))
    {
      fprintf (stderr, "%s:%i: gpgme_{set,get}_sender mismatch\n",
               PGM, __LINE__);
      exit (1);
    }

  err = gpgme_set_sender (ctx, "Foo bar (comment) <foo@example.org>");
  fail_if_err (err);
  s = gpgme_get_sender (ctx);
  if (!s || strcmp (s, "foo@example.org"))
    {
      fprintf (stderr, "%s:%i: gpgme_{set,get}_sender mismatch\n",
               PGM, __LINE__);
      exit (1);
    }

  err = gpgme_set_sender (ctx, "foo");
  if (gpgme_err_code (err) != GPG_ERR_INV_VALUE)
    {
      fprintf (stderr, "%s:%i: gpgme_set_sender didn't detect bogus address\n",
               PGM, __LINE__);
      exit (1);
    }
  /* (the former address should still be there.)  */
  s = gpgme_get_sender (ctx);
  if (!s || strcmp (s, "foo@example.org"))
    {
      fprintf (stderr, "%s:%i: gpgme_{set,get}_sender mismatch\n",
               PGM, __LINE__);
      exit (1);
    }


  gpgme_data_release (sig);
  gpgme_data_release (text);
  gpgme_release (ctx);
  return 0;
}

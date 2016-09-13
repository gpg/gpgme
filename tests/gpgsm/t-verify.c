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


static int got_errors;

static const char test_text1[] = "Hallo Leute!\n";
static const char test_text1f[]= "Hallo Leute?\n";
static const char test_sig1[] =
"-----BEGIN CMS OBJECT-----\n"
"MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAQAA\n"
"MYIBOTCCATUCAQEwcDBrMQswCQYDVQQGEwJERTETMBEGA1UEBxQKRPxzc2VsZG9y\n"
"ZjEWMBQGA1UEChMNZzEwIENvZGUgR21iSDEZMBcGA1UECxMQQWVneXB0ZW4gUHJv\n"
"amVjdDEUMBIGA1UEAxMLdGVzdCBjZXJ0IDECAQAwBwYFKw4DAhqgJTAjBgkqhkiG\n"
"9w0BCQQxFgQU7FC/ibH3lC9GE24RJJxa8zqP7wEwCwYJKoZIhvcNAQEBBIGAA3oC\n"
"DUmKERmD1eoJYFw38y/qnncS/6ZPjWINDIphZeK8mzAANpvpIaRPf3sNBznb89QF\n"
"mRgCXIWcjlHT0DTRLBf192Ve22IyKH00L52CqFsSN3a2sajqRUlXH8RY2D+Al71e\n"
"MYdRclgjObCcoilA8fZ13VR4DiMJVFCxJL4qVWI=\n"
"-----END CMS OBJECT-----\n";


static void
check_result (gpgme_verify_result_t result, int summary, const char *fpr,
	      gpgme_error_t status, gpgme_validity_t validity)
{
  gpgme_signature_t sig;

  sig = result->signatures;
  if (!sig || sig->next)
    {
      fprintf (stderr, "%s:%i: Unexpected number of signatures\n",
	       __FILE__, __LINE__);
      got_errors = 1;
      if (!sig)
        return;
    }
  if (sig->summary != summary)
    {
      fprintf (stderr, "%s:%i: Unexpected signature summary: "
               "want=0x%x have=0x%x\n",
	       __FILE__, __LINE__, summary, sig->summary);
      got_errors = 1;
    }
  if (sig->fpr && strcmp (sig->fpr, fpr))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
	       __FILE__, __LINE__, sig->fpr);
      got_errors = 1;
    }
  if (gpgme_err_code (sig->status) != status)
    {
      fprintf (stderr, "%s:%i: Unexpected signature status: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->status));
      got_errors = 1;
    }
  if (sig->notations)
    {
      fprintf (stderr, "%s:%i: Unexpected notation data\n",
	       __FILE__, __LINE__);
      got_errors = 1;
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i: Unexpectedly wrong key usage\n",
	       __FILE__, __LINE__);
      got_errors = 1;
    }
  if (sig->validity != validity)
    {
      fprintf (stderr, "%s:%i: Unexpected validity: %i\n",
	       __FILE__, __LINE__, sig->validity);
      got_errors = 1;
    }
  if (gpgme_err_code (sig->validity_reason) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "%s:%i: Unexpected validity reason: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (sig->validity_reason));
      got_errors = 1;
    }
}


static void
show_auditlog (gpgme_ctx_t ctx)
{
  gpgme_error_t err;
  gpgme_data_t data;

  err = gpgme_data_new (&data);
  fail_if_err (err);
  err = gpgme_op_getauditlog (ctx, data, 0);
  if (err)
    {
      fprintf (stderr, "%s:%i: Can't get audit log: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (err));
      if (gpgme_err_code (err) != GPG_ERR_ASS_UNKNOWN_CMD)
	got_errors = 1;
    }
  print_data (data);
  gpgme_data_release (data);
}



int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t sig, text;
  gpgme_verify_result_t result;

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

  /* Checking a valid message.  */
  err = gpgme_data_new_from_mem (&text, test_text1, strlen (test_text1), 0);
  fail_if_err (err);
  err = gpgme_data_new_from_mem (&sig, test_sig1, strlen (test_sig1), 0);
  fail_if_err (err);

  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, GPGME_SIGSUM_VALID | GPGME_SIGSUM_GREEN,
		"3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E",
		GPG_ERR_NO_ERROR, GPGME_VALIDITY_FULL);

  show_auditlog (ctx);

  /* Checking a manipulated message.  */
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&text, test_text1f, strlen (test_text1f), 0);
  fail_if_err (err);
  gpgme_data_seek (sig, 0, SEEK_SET);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  check_result (result, GPGME_SIGSUM_RED,
		"3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E",
		GPG_ERR_BAD_SIGNATURE, GPGME_VALIDITY_UNKNOWN);

  show_auditlog (ctx);

  gpgme_data_release (text);
  gpgme_data_release (sig);
  gpgme_release (ctx);
  return got_errors? 1 : 0;
}

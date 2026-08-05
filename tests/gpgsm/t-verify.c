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
static const char test_opaque_without_cert[] =
"-----BEGIN SIGNED MESSAGE-----\n"
"MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0B\n"
"BwGggCSABAlTaWduIG1lIQoAAAAAAAAxggLmMIIC4gIBATB+MHgxCzAJBgNVBAYT\n"
"AkRFMRYwFAYDVQQKEw1nMTAgQ29kZSBHbWJIMRAwDgYDVQQLEwdUZXN0bGFiMR4w\n"
"HAYDVQQDExVnMTAgQ29kZSBURVNUIENBIDIwMTkxHzAdBgkqhkiG9w0BCQEWEGlu\n"
"Zm9AZzEwY29kZS5jb20CAhoDMA0GCWCGSAFlAwQCAQUAoIG6MBgGCSqGSIb3DQEJ\n"
"AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDcyMjEyMjMzMlowLwYJ\n"
"KoZIhvcNAQkEMSIEIKmQZ0JOVOovrhBksV3YI2d7ilQAdZccUJYySVzZ0+tYME8G\n"
"CSqGSIb3DQEJDzFCMEAwCwYJYIZIAWUDBAEuMAsGCWCGSAFlAwQBBjALBglghkgB\n"
"ZQMEASowCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMHMA0GCSqGSIb3DQEBAQUABIIB\n"
"gJ0L7QAD5cOvgW+qETBWZIUwnyFRwUdQuNMC71X1SCRJdIzRPecr38Tt0i2dGXA2\n"
"Y7b6SGy9gOmy+DfqQ7GKPAmDyVqA1+sMOMnsF8CCB3DWdYbOWI18WAoPV49XOdra\n"
"vVTdXzKgz91WgXjiMUaG8Rrq7kP0F5Yw3LStUKZzO6yOof/YnJQWL9kYo/04m5Lj\n"
"ZkdwGW1o+WmFUcDO1OIEkxNmHWa/6wDlROT4HqH3ptwhXE9rMj8hA53tc7FlyACQ\n"
"pqe4U/GSTyoCUmPvdiiKc2SlM7JpiBtujUfIrIGyoPamsYodtQspdEeGzJaoSTwd\n"
"H9OJAmCRYIUrkAyE9XKediKkN7I7goQ0bbEUPMLCBuYGlaLmi6mjsdkXgBYDCfdl\n"
"Lp5y93zATlDCNfFtFnpaNsdCiGGRiLQKZOGEfsySa3DSMqXy+CUkv51VVkPf2i9D\n"
"Qx6gF4XphsJU9W0S+vjSCAFQ6e6zdAKduVLaTRrw29s11uNGdFebcMMPxGlGsNOd\n"
"jQAAAAAAAA==\n"
"-----END SIGNED MESSAGE-----\n";


static void
check_result (gpgme_verify_result_t result, int summary, const char *fpr,
              const char *issuer_serial, const char *issuer_name,
	      gpgme_error_t status, gpgme_validity_t validity,
              unsigned long timestamp)
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
  if (safe_strcmp (sig->fpr, fpr))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
	       __FILE__, __LINE__, nonnull (sig->fpr));
      got_errors = 1;
    }
  if (safe_strcmp (sig->issuer_serial, issuer_serial))
    {
      fprintf (stderr, "%s:%i: Unexpected s/n: %s\n",
	       __FILE__, __LINE__, nonnull (sig->issuer_serial));
      got_errors = 1;
    }
  if (safe_strcmp (sig->issuer_name, issuer_name))
    {
      fprintf (stderr, "%s:%i: Unexpected issuer: %s\n",
	       __FILE__, __LINE__, nonnull (sig->issuer_name));
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
  if (sig->timestamp != timestamp)
    {
     fprintf (stderr, "%s:%i: Unexpected timestamp: "
              "want=%li have=%li\n",
	      __FILE__, __LINE__, timestamp, sig->timestamp);
      exit (1);
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
		"3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E", NULL, NULL,
		GPG_ERR_NO_ERROR, GPGME_VALIDITY_FULL, 0);

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
		"3CF405464F66ED4A7DF45BBDD1E4282E33BDB76E", NULL, NULL,
		GPG_ERR_BAD_SIGNATURE, GPGME_VALIDITY_UNKNOWN, 0);

  show_auditlog (ctx);

  /* Checking a message without embedded signing certificate.  */
  gpgme_data_release (sig);
  gpgme_data_release (text);
  err = gpgme_data_new_from_mem (&sig, test_opaque_without_cert,
                                 strlen (test_opaque_without_cert), 0);
  fail_if_err (err);
  err = gpgme_data_new (&text);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, NULL, text);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);
  if (have_gpgsm_version ("2.5.22"))
    check_result (result, GPGME_SIGSUM_KEY_MISSING,
		  NULL, "1A03",
		  "1.2.840.113549.1.9.1=#696E666F40673130636F64652E636F6D,"
		  "CN=g10 Code TEST CA 2019,OU=Testlab,O=g10 Code GmbH,C=DE",
		  GPG_ERR_NO_PUBKEY, GPGME_VALIDITY_UNKNOWN, 0);
  else
    check_result (result, GPGME_SIGSUM_KEY_MISSING,
		  NULL, NULL, NULL,
		  GPG_ERR_NO_PUBKEY, GPGME_VALIDITY_UNKNOWN, 0);

  show_auditlog (ctx);

  gpgme_data_release (text);
  gpgme_data_release (sig);
  gpgme_release (ctx);

  return got_errors? 1 : 0;
}

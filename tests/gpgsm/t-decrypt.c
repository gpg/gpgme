/* t-encrypt.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003, 2004 g10 Code GmbH

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
#include <errno.h>

#include <gpgme.h>
#include "t-support.h"


static const char test_text1[] = "Hallo Leute!\n";
static const char test_cip1[] =
"-----BEGIN CMS OBJECT-----\n"
"MIAGCSqGSIb3DQEHA6CAMIACAQAxggEJMIIBBQIBADBwMGsxCzAJBgNVBAYTAkRF\n"
"MRMwEQYDVQQHFApE/HNzZWxkb3JmMRYwFAYDVQQKEw1nMTAgQ29kZSBHbWJIMRkw\n"
"FwYDVQQLExBBZWd5cHRlbiBQcm9qZWN0MRQwEgYDVQQDEwt0ZXN0IGNlcnQgMQIB\n"
"ADALBgkqhkiG9w0BAQEEgYBOFcOfUtAav+XjKGM1RJtF+8JLkbnu46S3T3709Iok\n"
"u+Z9dwpOyfHwxXOmjzkSKQSBBxxi6ar+sKjU/KfPIvaMpARwT+NfIVSCZRWIJ27z\n"
"wbSrav/kcRRDDA0wXV7dHVmSLPUJNCpiFMNZbkYtI+ai15g0PVeDw+szYd9zdsjJ\n"
"2zCABgkqhkiG9w0BBwEwFAYIKoZIhvcNAwcECA8gPQY2NtJToIAECAeoY3MIcz9h\n"
"BAiiytWtOSmqnwAA\n"
"-----END CMS OBJECT-----\n";


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_decrypt_result_t result;

  init_gpgme (GPGME_PROTOCOL_CMS);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);

  err = gpgme_data_new_from_mem (&in, test_cip1, strlen (test_cip1), 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_decrypt (ctx, in, out);
  fail_if_err (err);
  result = gpgme_op_decrypt_result (ctx);
  if (result->unsupported_algorithm)
    {
      fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	       __FILE__, __LINE__, result->unsupported_algorithm);
      exit (1);
    }
  print_data (out);

  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}

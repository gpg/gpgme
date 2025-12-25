/* t-decrypt-verify.c - Regression test.
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
#include <errno.h>
#include <unistd.h>

#include <gpgme.h>

#include "t-support.h"


static const char normal_signed_message[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n"
"GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n"
"y1kvP4y+8D5a11ang0udywsA\n"
"=Crq6\n"
"-----END PGP MESSAGE-----\n";


static void
check_verify_result (gpgme_verify_result_t result, unsigned int summary,
		     const char *fpr, gpgme_error_t status, int validity)
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
      fprintf (stderr, "%s:%i: Unexpected signature summary: 0x%x\n",
	       __FILE__, __LINE__, sig->summary);
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
  if (sig->notations)
    {
      fprintf (stderr, "%s:%i: Unexpected notation data\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->wrong_key_usage)
    {
      fprintf (stderr, "%s:%i: Unexpectedly wrong key usage\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (sig->validity != validity)
    {
      fprintf (stderr, "%s:%i: Unexpected validity: "
               "want=%i have=%i\n",
	       __FILE__, __LINE__, validity, sig->validity);
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
  gpgme_data_t in, out;
  gpgme_decrypt_result_t decrypt_result;
  gpgme_verify_result_t verify_result;
  char *cipher_2_asc = make_filename ("cipher-2.asc");
  char *agent_info;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }

  err = gpgme_data_new_from_file (&in, cipher_2_asc, 1);
  free (cipher_2_asc);
  fail_if_err (err);
  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_decrypt_verify (ctx, in, out);
  fail_if_err (err);
  decrypt_result = gpgme_op_decrypt_result (ctx);
  if (decrypt_result->unsupported_algorithm)
    {
      fprintf (stderr, "%s:%i: unsupported algorithm: %s\n",
	       __FILE__, __LINE__, decrypt_result->unsupported_algorithm);
      exit (1);
    }
  print_data (out);
  verify_result = gpgme_op_verify_result (ctx);
  check_verify_result (verify_result, GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN,
		       "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		       GPG_ERR_NO_ERROR, GPGME_VALIDITY_FULL);

  gpgme_data_release (in);
  gpgme_data_release (out);

  /* Checking a signed, but not encrypted message.  */
  err = gpgme_data_new_from_mem (&in, normal_signed_message, strlen (normal_signed_message), 0);
  fail_if_err (err);
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_decrypt_verify (ctx, in, out);
  /* should have returned "no data" because the message is not encrypted */
  if (gpgme_err_code (err) != GPG_ERR_NO_DATA)
    {
      fprintf (stderr, "%s:%i: Unexpected result of gpgme_op_decrypt_verify: %s\n",
	       __FILE__, __LINE__, gpgme_strerror (err));
    }
  verify_result = gpgme_op_verify_result (ctx);
  check_verify_result (verify_result, GPGME_SIGSUM_VALID|GPGME_SIGSUM_GREEN,
		       "A0FF4590BB6122EDEF6E3C542D727CC768697734",
		       GPG_ERR_NO_ERROR, GPGME_VALIDITY_FULL);

  gpgme_data_release (in);
  gpgme_data_release (out);

  gpgme_release (ctx);
  return 0;
}

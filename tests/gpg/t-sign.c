/* t-sign.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2003, 2004 g10 Code GmbH
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
#include <unistd.h>

#include <gpgme.h>

#include "t-support.h"


static void
check_result (gpgme_sign_result_t result, gpgme_sig_mode_t type)
{
  if (result->invalid_signers)
    {
      fprintf (stderr, "Invalid signer found: %s\n",
	       result->invalid_signers->fpr);
      exit (1);
    }
  if (!result->signatures || result->signatures->next)
    {
      fprintf (stderr, "Unexpected number of signatures created\n");
      exit (1);
    }
  if (result->signatures->type != type)
    {
      fprintf (stderr, "Wrong type of signature created\n");
      exit (1);
    }
  if (result->signatures->pubkey_algo != GPGME_PK_DSA)
    {
      fprintf (stderr, "Wrong pubkey algorithm reported: %i\n",
	       result->signatures->pubkey_algo);
      exit (1);
    }
  if (result->signatures->hash_algo != GPGME_MD_SHA1)
    {
      fprintf (stderr, "Wrong hash algorithm reported: %i\n",
	       result->signatures->hash_algo);
      exit (1);
    }
  if (result->signatures->sig_class != 1)
    {
      fprintf (stderr, "Wrong signature class reported: %u\n",
	       result->signatures->sig_class);
      exit (1);
    }
  if (strcmp ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
	      result->signatures->fpr))
    {
      fprintf (stderr, "Wrong fingerprint reported: %s\n",
	       result->signatures->fpr);
      exit (1);
    }
}


int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_sign_result_t result;
  char *agent_info;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  agent_info = getenv ("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }

  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

#if 0
  {
    gpgme_key_t akey;
    err = gpgme_get_key (ctx, "0x68697734", &akey, 0);
    fail_if_err (err);
    err = gpgme_signers_add (ctx, akey);
    fail_if_err (err);
    gpgme_key_unref (akey);
  }
#endif

  err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
  fail_if_err (err);

  /* First a normal signature.  */
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_NORMAL);
  fail_if_err (err);
  result = gpgme_op_sign_result (ctx);
  check_result (result, GPGME_SIG_MODE_NORMAL);
  print_data (out);
  gpgme_data_release (out);

  /* Now a detached signature.  */
  gpgme_data_seek (in, 0, SEEK_SET);
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_DETACH);
  fail_if_err (err);
  result = gpgme_op_sign_result (ctx);
  check_result (result, GPGME_SIG_MODE_DETACH);
  print_data (out);
  gpgme_data_release (out);

  /* And finally a cleartext signature.  */
  gpgme_data_seek (in, 0, SEEK_SET);
  err = gpgme_data_new (&out);
  fail_if_err (err);
  err = gpgme_op_sign (ctx, in, out, GPGME_SIG_MODE_CLEAR);
  fail_if_err (err);
  result = gpgme_op_sign_result (ctx);
  check_result (result, GPGME_SIG_MODE_CLEAR);
  print_data (out);
  gpgme_data_release (out);

  gpgme_data_release (in);
  gpgme_release (ctx);
  return 0;
}

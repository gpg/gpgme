/* t-signers.c - Regression tests for the multiple signers interface.
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
  gpgme_new_signature_t signature;

  if (result->invalid_signers)
    {
      fprintf (stderr, "Invalid signer found: %s\n",
	       result->invalid_signers->fpr);
      exit (1);
    }
  if (!result->signatures || !result->signatures->next
      || result->signatures->next->next)
    {
      fprintf (stderr, "Unexpected number of signatures created\n");
      exit (1);
    }

  signature = result->signatures;
  while (signature)
    {
      if (signature->type != type)
	{
	  fprintf (stderr, "Wrong type of signature created\n");
	  exit (1);
	}
      if (signature->pubkey_algo != GPGME_PK_DSA)
	{
	  fprintf (stderr, "Wrong pubkey algorithm reported: %i\n",
		   signature->pubkey_algo);
	  exit (1);
	}
      if (signature->hash_algo != GPGME_MD_SHA1)
	{
	  fprintf (stderr, "Wrong hash algorithm reported: %i\n",
		   signature->hash_algo);
	  exit (1);
	}
      if (signature->sig_class != 1)
	{
	  fprintf (stderr, "Wrong signature class reported: %u\n",
		   signature->sig_class);
	  exit (1);
	}
      if (strcmp ("A0FF4590BB6122EDEF6E3C542D727CC768697734",
		   signature->fpr)
	  && strcmp ("23FD347A419429BACCD5E72D6BC4778054ACD246",
		     signature->fpr))
	{
	  fprintf (stderr, "Wrong fingerprint reported: %s\n",
		   signature->fpr);
	  exit (1);
	}
      signature = signature->next;
    }
}


int
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t key[2];
  gpgme_sign_result_t result;
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

  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  err = gpgme_op_keylist_start (ctx, NULL, 1);
  fail_if_err (err);
  err = gpgme_op_keylist_next (ctx, &key[0]);
  fail_if_err (err);
  err = gpgme_op_keylist_next (ctx, &key[1]);
  fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);

  err = gpgme_signers_add (ctx, key[0]);
  fail_if_err (err);
  err = gpgme_signers_add (ctx, key[1]);
  fail_if_err (err);

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
  gpgme_data_seek (in, 0, SEEK_SET);

  gpgme_data_release (in);
  gpgme_release (ctx);

  gpgme_key_unref (key[0]);
  gpgme_key_unref (key[1]);
  return 0;
}

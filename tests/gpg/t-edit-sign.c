/* t-edit-sign.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2021 g10 Code GmbH
 * Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>

#include <gpgme.h>

#include "t-support.h"


static void
flush_data (gpgme_data_t dh)
{
  char buf[100];
  int ret;

  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (gpgme_error_from_errno (errno));
  while ((ret = gpgme_data_read (dh, buf, 100)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (gpgme_error_from_errno (errno));
}


gpgme_error_t
interact_fnc (void *opaque, const char *status, const char *args, int fd)
{
  const char *result = NULL;
  gpgme_data_t out = (gpgme_data_t) opaque;

  fputs ("[-- Response --]\n", stdout);
  flush_data (out);

  fprintf (stdout, "[-- Code: %s, %s --]\n", status, args);

  if (fd >= 0)
    {
      if (!strcmp (args, "keyedit.prompt"))
	{
	  static int step = 0;

	  switch (step)
	    {
	    case 0:
	      result = "fpr";
	      break;
	    case 1:
	      /* This fixes the primary user ID so the keylisting
		 tests will have predictable output.  */
	      result = "1";
	      break;
	    case 2:
	      result = "sign";
	      break;

	    default:
	      result = "quit";
	      break;
	    }
	  step++;
	}
      else if (!strcmp (args, "keyedit.save.okay"))
	result = "Y";
      else if (!strcmp (args, "sign_uid.okay"))
	result = "Y";
    }

  if (result)
    gpgme_io_writen (fd, result, strlen (result));
  gpgme_io_writen (fd, "\n", 1);
  return 0;
}


void
sign_key (const char *key_fpr, const char *signer_fpr)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t signing_key = NULL;
  gpgme_key_t key = NULL;
  char *agent_info;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    gpgme_set_passphrase_cb (ctx, passphrase_cb, 0);

  err = gpgme_get_key (ctx, signer_fpr, &signing_key, 1);
  fail_if_err (err);
  err = gpgme_signers_add (ctx, signing_key);
  fail_if_err (err);

  err = gpgme_set_ctx_flag (ctx, "cert-expire", "42d");
  fail_if_err (err);

  err = gpgme_get_key (ctx, key_fpr, &key, 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_op_interact (ctx, key, 0, interact_fnc, out, out);
  fail_if_err (err);

  fputs ("[-- Last response --]\n", stdout);
  flush_data (out);

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_key_unref (signing_key);
  gpgme_release (ctx);
}


void
verify_key_signature (const char *key_fpr, const char *signer_keyid)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_key_t signed_key = NULL;
  gpgme_user_id_t signed_uid = NULL;
  gpgme_key_sig_t key_sig = NULL;
  int mode;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  mode  = gpgme_get_keylist_mode (ctx);
  mode |= GPGME_KEYLIST_MODE_SIGS;
  err = gpgme_set_keylist_mode (ctx, mode);
  fail_if_err (err);
  err = gpgme_get_key (ctx, key_fpr, &signed_key, 0);
  fail_if_err (err);

  signed_uid = signed_key->uids;
  if (!signed_uid)
    {
      fprintf (stderr, "Signed key has no user IDs\n");
      exit (1);
    }
  if (!signed_uid->signatures || !signed_uid->signatures->next)
    {
      fprintf (stderr, "Signed user ID has less signatures than expected\n");
      exit (1);
    }
  key_sig = signed_uid->signatures->next;
  if (strcmp (signer_keyid, key_sig->keyid))
    {
      fprintf (stderr, "Unexpected key ID in second user ID sig: %s\n",
                key_sig->keyid);
      exit (1);
    }
  if (key_sig->expires != key_sig->timestamp + 42*86400L)
    {
      fprintf (stderr, "Key signature unexpectedly does not expire in 42 days\n");
      fprintf (stderr, "signature date: %ld, expiration date: %ld\n",
               key_sig->timestamp, key_sig->expires);
      exit (1);
    }

  gpgme_key_unref (signed_key);
  gpgme_release (ctx);
}


int
main (int argc, char **argv)
{
  const char *signer_fpr = "A0FF4590BB6122EDEF6E3C542D727CC768697734"; /* Alpha Test */
  const char *signer_keyid = signer_fpr + strlen(signer_fpr) - 16;
  const char *key_fpr = "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2"; /* Bravo Test */

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  sign_key (key_fpr, signer_fpr);
  verify_key_signature (key_fpr, signer_keyid);

  return 0;
}

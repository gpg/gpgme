/* t-edit.c - Regression test.
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
	      result = "expire";
	      break;

	      /* This fixes the primary user ID so the keylisting
		 tests will have predictable output.  */
	    case 2:
	      result = "1";
	      break;
	    case 3:
	      result = "primary";
	      break;

	    default:
	      result = "quit";
	      break;
	    }
	  step++;
	}
      else if (!strcmp (args, "keyedit.save.okay"))
	result = "Y";
      else if (!strcmp (args, "keygen.valid"))
	result = "0";
    }

  if (result)
    {
      gpgme_io_writen (fd, result, strlen (result));
      gpgme_io_writen (fd, "\n", 1);
    }
  return 0;
}


int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  const char *pattern = "Alpha";
  char *agent_info;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  err = gpgme_data_new (&out);
  fail_if_err (err);

  agent_info = getenv("GPG_AGENT_INFO");
  if (!(agent_info && strchr (agent_info, ':')))
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, 0);
    }

  err = gpgme_op_keylist_start (ctx, pattern, 0);
  fail_if_err (err);
  err = gpgme_op_keylist_next (ctx, &key);
  fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);

  err = gpgme_op_interact (ctx, key, 0, interact_fnc, out, out);
  fail_if_err (err);

  fputs ("[-- Last response --]\n", stdout);
  flush_data (out);

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  return 0;
}

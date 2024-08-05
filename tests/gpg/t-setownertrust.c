/* t-setownertrust.c - Regression test.
 * Copyright (C) 2024 g10 Code GmbH
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

#define PGM "t-setownertrust"
#include "t-support.h"

#include <gpgme.h>

#include <stdio.h>
#include <stdlib.h>


static gpgme_key_t
list_one_key (gpgme_ctx_t ctx, const char *pattern, int secret_only)
{
  gpgme_error_t err;
  gpgme_key_t key = NULL;

  err = gpgme_op_keylist_start (ctx, pattern, secret_only);
  fail_if_err (err);
  err = gpgme_op_keylist_next (ctx, &key);
  fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);

  return key;
}


int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_key_t key = NULL;
  const char *pattern = "Alpha";

  (void)argc;
  (void)argv;

  if (!have_gpg_version ("2.4.6"))
    {
      printf ("Testsuite skipped. Minimum GnuPG version (2.4.6) "
              "not found.\n");
      exit(0);
    }

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  key = list_one_key (ctx, pattern, 0);
  err = gpgme_op_setownertrust (ctx, key, "disable");
  fail_if_err (err);
  gpgme_key_unref (key);

  key = list_one_key (ctx, pattern, 0);
  if (!key->disabled)
    {
      fprintf (stderr, "%s:%i: Key is unexpectedly not disabled\n",
               PGM, __LINE__);
      exit (1);
    }
  gpgme_key_unref (key);

  key = list_one_key (ctx, pattern, 0);
  err = gpgme_op_setownertrust (ctx, key, "enable");
  fail_if_err (err);
  gpgme_key_unref (key);

  key = list_one_key (ctx, pattern, 0);
  if (key->disabled)
    {
      fprintf (stderr, "%s:%i: Key is unexpectedly disabled\n",
               PGM, __LINE__);
      exit (1);
    }
  gpgme_key_unref (key);

  /* Check error handling */
  err = gpgme_op_setownertrust (ctx, NULL, "ultimate");
  if (gpgme_err_code (err) != GPG_ERR_INV_VALUE)
    {
      fprintf (stderr, "%s:%i: Unexpected error code: %s\n",
	       PGM, __LINE__, gpgme_strerror (err));
      exit (1);
    }
  key = list_one_key (ctx, pattern, 0);
  err = gpgme_op_setownertrust (ctx, key, NULL);
  if (gpgme_err_code (err) != GPG_ERR_INV_VALUE)
    {
      fprintf (stderr, "%s:%i: Unexpected error code: %s\n",
	       PGM, __LINE__, gpgme_strerror (err));
      exit (1);
    }
  err = gpgme_op_setownertrust (ctx, key, "");
  if (gpgme_err_code (err) != GPG_ERR_INV_VALUE)
    {
      fprintf (stderr, "%s:%i: Unexpected error code: %s\n",
	       PGM, __LINE__, gpgme_strerror (err));
      exit (1);
    }
  gpgme_key_unref (key);

  gpgme_release (ctx);

  return 0;
}

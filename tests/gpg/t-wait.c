/* t-wait.c - Regression test.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007 g10 Code GmbH
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

#ifdef HAVE_W32_SYSTEM
#define sleep(seconds) Sleep(seconds*1000)
#endif

#include <gpgme.h>

#include "t-support.h"


int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t sig, text;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  /* Checking a message without a signature.  */
  err = gpgme_data_new_from_mem (&sig, "foo\n", 4, 0);
  fail_if_err (err);
  err = gpgme_data_new (&text);
  fail_if_err (err);
  err = gpgme_op_verify_start (ctx, sig, NULL, text);
  fail_if_err (err);

  while (gpgme_wait (ctx, &err, 0) == NULL && err == 0)
    sleep(1);

  if (gpgme_err_code (err) != GPG_ERR_NO_DATA)
    {
      fprintf (stderr, "%s:%d: %s: %s\n",
	       __FILE__, __LINE__, gpgme_strsource (err),
	       gpgme_strerror (err));
      exit (1);
    }

  gpgme_data_release (sig);
  gpgme_data_release (text);
  gpgme_release (ctx);
  return 0;
}

/* t-encrypt-sym.c - Regression test.
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
#include <unistd.h>

#include <gpgme.h>

#include "t-support.h"


int
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t plain, cipher;
  const char *text = "Hallo Leute\n";
  char *text2;
  char *p;
  size_t len;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 1);

  p = getenv("GPG_AGENT_INFO");
  if (!(p && strchr (p, ':')))
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }

  err = gpgme_data_new_from_mem (&plain, text, strlen (text), 0);
  fail_if_err (err);

  err = gpgme_data_new (&cipher);
  fail_if_err (err);

  err = gpgme_op_encrypt (ctx, 0, 0, plain, cipher);
  fail_if_err (err);

  fflush (NULL);
  fputs ("Begin Result Encryption:\n", stdout);
  print_data (cipher);
  fputs ("End Result.\n", stdout);

  gpgme_data_seek (cipher, 0, SEEK_SET);

  gpgme_data_release (plain);
  err = gpgme_data_new (&plain);
  fail_if_err (err);

  err = gpgme_op_decrypt (ctx, cipher, plain);
  fail_if_err (err);

  fputs ("Begin Result Decryption:\n", stdout);
  print_data (plain);
  fputs ("End Result.\n", stdout);

  text2 = gpgme_data_release_and_get_mem (plain, &len);
  if (strncmp (text, text2, len))
    {
      fprintf (stderr, "%s:%d: Wrong plaintext\n", __FILE__, __LINE__);
      exit (1);
    }

  gpgme_data_release (cipher);
  free (text2);
  gpgme_release (ctx);

  return 0;
}

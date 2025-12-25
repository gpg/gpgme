/* t-encrypt-mixed.c - Regression test.
 * Copyright (C) 2016 by Bundesamt für Sicherheit in der Informationstechnik
 * Software engineering by Intevation GmbH
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#include "t-support.h"

/* Tests mixed symmetric and asymmetric decryption. Verifies
   that an encrypted message can be decrypted without the
   secret key but that the recipient is also set correctly. */
int
main (void)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t key[2] = { NULL, NULL };
  gpgme_encrypt_result_t result;
  gpgme_decrypt_result_t dec_result;
  gpgme_recipient_t recipient;
  const char *text = "Hallo Leute\n";
  char *text2;
  size_t len;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 1);

  err = gpgme_data_new_from_mem (&in, text, strlen (text), 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
  gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

  /* A recipient for which we don't have a secret key */
  err = gpgme_get_key (ctx, "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2",
                       &key[0], 0);
  fail_if_err (err);

  err = gpgme_op_encrypt (ctx, key,
                          GPGME_ENCRYPT_ALWAYS_TRUST | GPGME_ENCRYPT_SYMMETRIC,
                          in, out);
  fail_if_err (err);
  result = gpgme_op_encrypt_result (ctx);
  if (result->invalid_recipients)
    {
      fprintf (stderr, "Invalid recipient encountered: %s\n",
               result->invalid_recipients->fpr);
      exit (1);
    }

  print_data (out);

  /* Now try to decrypt */
  gpgme_data_seek (out, 0, SEEK_SET);

  gpgme_data_release (in);
  err = gpgme_data_new (&in);
  fail_if_err (err);

  err = gpgme_op_decrypt (ctx, out, in);
  fail_if_err (err);

  fputs ("Begin Result Decryption:\n", stdout);
  print_data (in);
  fputs ("End Result.\n", stdout);

  dec_result = gpgme_op_decrypt_result (ctx);
  if (dec_result->unsupported_algorithm || dec_result->wrong_key_usage)
    {
      fprintf (stderr, "%s:%d: Decryption failed\n", __FILE__, __LINE__);
      exit (1);
    }

  text2 = gpgme_data_release_and_get_mem (in, &len);
  if (strncmp (text, text2, len))
    {
      fprintf (stderr, "%s:%d: Wrong plaintext\n", __FILE__, __LINE__);
      exit (1);
    }

  recipient = dec_result->recipients;
  if (!recipient || recipient->next)
    {
      fprintf (stderr, "%s:%d: Invalid recipients \n", __FILE__, __LINE__);
      exit (1);
    }

  if (strncmp (recipient->keyid, "5381EA4EE29BA37F", 16))
    {
      fprintf (stderr, "%s:%d: Not encrypted to recipient's subkey \n", __FILE__, __LINE__);
      exit (1);
    }

  gpgme_key_unref (key[0]);
  free (text2);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}

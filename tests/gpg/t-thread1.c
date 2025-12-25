/* t-thread1.c - Regression test.
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
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <gpgme.h>

#include "t-support.h"

#define ROUNDS 20


void *
thread_one (void *name)
{
  int i;

  for (i = 0; i < ROUNDS; i++)
    {
      gpgme_ctx_t ctx;
      gpgme_error_t err;
      gpgme_data_t in, out;
      gpgme_key_t key[3] = { NULL, NULL, NULL };
      gpgme_encrypt_result_t result;

      err = gpgme_new (&ctx);
      fail_if_err (err);
      gpgme_set_armor (ctx, 1);

      err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
      fail_if_err (err);

      err = gpgme_data_new (&out);
      fail_if_err (err);

      err = gpgme_get_key (ctx, "A0FF4590BB6122EDEF6E3C542D727CC768697734",
			   &key[0], 0);
      fail_if_err (err);
      err = gpgme_get_key (ctx, "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2",
			   &key[1], 0);
      fail_if_err (err);

      err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
      fail_if_err (err);
      result = gpgme_op_encrypt_result (ctx);
      if (result->invalid_recipients)
	{
	  fprintf (stderr, "Invalid recipient encountered: %s\n",
		   result->invalid_recipients->fpr);
	  exit (1);
	}
      printf ("Encrypt %s %i\n", (char *) name, i);

      gpgme_key_unref (key[0]);
      gpgme_key_unref (key[1]);
      gpgme_data_release (in);
      gpgme_data_release (out);
      gpgme_release (ctx);
    }
  return NULL;
}


void *
thread_two (void *name)
{
  int i;
  char *cipher_1_asc = make_filename ("cipher-1.asc");
  char *agent_info;

  agent_info = getenv("GPG_AGENT_INFO");

  for (i = 0; i < ROUNDS; i++)
    {
      gpgme_ctx_t ctx;
      gpgme_error_t err;
      gpgme_data_t in, out;
      gpgme_decrypt_result_t result;

      init_gpgme (GPGME_PROTOCOL_OpenPGP);

      err = gpgme_new (&ctx);
      fail_if_err (err);

      if (!(agent_info && strchr (agent_info, ':')))
        {
          gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
          gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
        }

      err = gpgme_data_new_from_file (&in, cipher_1_asc, 1);
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
      printf ("Decrypt %s %i\n", (char *) name, i);

      gpgme_data_release (in);
      gpgme_data_release (out);
      gpgme_release (ctx);
    }
  free (cipher_1_asc);
  return NULL;
}

int
main (void)
{
  pthread_t tone;
  pthread_t ttwo;
  char arg_A[] = "A";
  char arg_B[] = "B";

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  pthread_create (&tone, NULL, thread_one, arg_A);
  pthread_create (&ttwo, NULL, thread_two, arg_B);

  pthread_join (tone, NULL);
  pthread_join (ttwo, NULL);

  return 0;
}

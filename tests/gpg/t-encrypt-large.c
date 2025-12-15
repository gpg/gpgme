/* t-encrypt-large.c - Regression test for large amounts of data.
 * Copyright (C) 2005 g10 Code GmbH
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

#include <gpgme.h>

#include "t-support.h"


struct cb_parms
{
  size_t bytes_to_send;
  size_t bytes_received;
};



/* The read callback used by GPGME to read data. */
static gpgme_ssize_t
read_cb (void *handle, void *buffer, size_t size)
{
  struct cb_parms *parms = handle;
  char *p = buffer;

  for (; size && parms->bytes_to_send; size--, parms->bytes_to_send--)
    *p++ = rand ();

  return (p - (char*)buffer);
}

/* The write callback used by GPGME to write data. */
static gpgme_ssize_t
write_cb (void *handle, const void *buffer, size_t size)
{
  struct cb_parms *parms = handle;

  (void)buffer;

  parms->bytes_received += size;

  return size;
}


static void
progress_cb (void *opaque, const char *what, int type, int current, int total)
{
  /* This is just a dummy. */
  (void)opaque;
  (void)what;
  (void)type;
  (void)current;
  (void)total;
}





int
main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  struct gpgme_data_cbs cbs;
  gpgme_data_t in, out;
  gpgme_key_t key[3] = { NULL, NULL, NULL };
  gpgme_encrypt_result_t result;
  size_t nbytes;
  struct cb_parms parms;

  if (argc > 1)
    nbytes = atoi (argv[1]);
  else
    nbytes = 100000;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  memset (&cbs, 0, sizeof cbs);
  cbs.read = read_cb;
  cbs.write = write_cb;
  memset (&parms, 0, sizeof parms);
  parms.bytes_to_send = nbytes;

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 0);

  /* Install a progress handler to enforce a bit of more work to the
     gpgme i/o system. */
  gpgme_set_progress_cb (ctx, progress_cb, NULL);

  err = gpgme_data_new_from_cbs (&in, &cbs, &parms);
  fail_if_err (err);

  err = gpgme_data_new_from_cbs (&out, &cbs, &parms);
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
  printf ("plaintext=%u bytes, ciphertext=%u bytes\n",
          (unsigned int)nbytes, (unsigned int)parms.bytes_received);

  gpgme_key_unref (key[0]);
  gpgme_key_unref (key[1]);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}

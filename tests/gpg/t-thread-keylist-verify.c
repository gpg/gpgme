/* t-thread-verify.c - Regression test.
 * Copyright (C) 2015 by Bundesamt für Sicherheit in der Informationstechnik
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

#include <pthread.h>

#include "t-support.h"

#define THREAD_COUNT 10

static const char test_text1[] = "Just GNU it!\n";
static const char test_sig1[] =
"-----BEGIN PGP SIGNATURE-----\n"
"\n"
"iN0EABECAJ0FAjoS+i9FFIAAAAAAAwA5YmFyw7bDpMO8w58gZGFzIHdhcmVuIFVt\n"
"bGF1dGUgdW5kIGpldHp0IGVpbiBwcm96ZW50JS1aZWljaGVuNRSAAAAAAAgAJGZv\n"
"b2Jhci4xdGhpcyBpcyBhIG5vdGF0aW9uIGRhdGEgd2l0aCAyIGxpbmVzGhpodHRw\n"
"Oi8vd3d3Lmd1Lm9yZy9wb2xpY3kvAAoJEC1yfMdoaXc0JBIAoIiLlUsvpMDOyGEc\n"
"dADGKXF/Hcb+AKCJWPphZCphduxSvrzH0hgzHdeQaA==\n"
"=nts1\n"
"-----END PGP SIGNATURE-----\n";

void *
start_keylist (void *arg)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;

  (void)arg;
  err = gpgme_new (&ctx);
  fail_if_err (err);

  err = gpgme_op_keylist_start (ctx, NULL, 0);
  fail_if_err (err);

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_key_unref (key);
    }

  gpgme_release (ctx);
  return NULL;
}

void *
start_verify (void *arg)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t sig, text;
  gpgme_verify_result_t result;
  gpgme_signature_t signature;

  (void)arg;

  err = gpgme_new (&ctx);
  fail_if_err (err);

  /* Checking a valid message.  */
  err = gpgme_data_new_from_mem (&text, test_text1, strlen (test_text1), 0);
  fail_if_err (err);
  err = gpgme_data_new_from_mem (&sig, test_sig1, strlen (test_sig1), 0);
  fail_if_err (err);
  err = gpgme_op_verify (ctx, sig, text, NULL);
  fail_if_err (err);
  result = gpgme_op_verify_result (ctx);

  signature = result->signatures;

  if (strcmp (signature->fpr, "A0FF4590BB6122EDEF6E3C542D727CC768697734"))
    {
      fprintf (stderr, "%s:%i: Unexpected fingerprint: %s\n",
               __FILE__, __LINE__, signature->fpr);
      exit (1);
    }
  if (gpgme_err_code (signature->status) != GPG_ERR_NO_ERROR)
    {
      fprintf (stderr, "%s:%i: Unexpected signature status: %s\n",
               __FILE__, __LINE__, gpgme_strerror (signature->status));
      exit (1);
    }
  gpgme_free (text);
  gpgme_free (sig);
  gpgme_release (ctx);
  return NULL;
}

int
main (int argc, char *argv[])
{
  int i;
  pthread_t verify_threads[THREAD_COUNT];
  pthread_t keylist_threads[THREAD_COUNT];
  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  (void)argc;
  (void)argv;

  for (i = 0; i < THREAD_COUNT; i++)
    {
      if (pthread_create(&verify_threads[i], NULL, start_verify, NULL) ||
          pthread_create(&keylist_threads[i], NULL, start_keylist, NULL))
        {
          fprintf(stderr, "%s:%i: failed to create threads \n",
                       __FILE__, __LINE__);
          exit(1);
        }
   }
  for (i = 0; i < THREAD_COUNT; i++)
    {
      pthread_join (verify_threads[i], NULL);
      pthread_join (keylist_threads[i], NULL);
    }
  return 0;
}

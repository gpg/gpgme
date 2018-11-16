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

void *
start_keylist (void *arg)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;

  (void) arg;
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

int
main (int argc, char *argv[])
{
  int i;
  pthread_t keylist_threads[THREAD_COUNT];
  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  (void)argc;
  (void)argv;

  for (i = 0; i < THREAD_COUNT; i++)
    {
      if (pthread_create(&keylist_threads[i], NULL, start_keylist, NULL))
        {
          fprintf(stderr, "%s:%i: failed to create threads \n",
                       __FILE__, __LINE__);
          exit(1);
        }
   }
  for (i = 0; i < THREAD_COUNT; i++)
    {
      pthread_join (keylist_threads[i], NULL);
    }
  return 0;
}

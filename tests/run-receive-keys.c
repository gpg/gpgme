/* run-keylist.c  - Helper to show a key listing.
 * Copyright (C) 2008, 2009 g10 Code GmbH
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
#include <time.h>

#include <gpgme.h>

#define PGM "run-receive-keys"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [KEYIDs_or_FINGERPRINTs]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  const char *keyids[100];
  const char **keyid = NULL;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_import_result_t impres;


  if (argc)
    { argc--; argv++; }

  while (argc && last_argc != argc)
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        show_usage (0);
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (!argc)
    show_usage (1);
  if (argc > 99) {
    argc = 99;
  }
  for (keyid = keyids; argc; argc--, argv++, keyid++) {
    *keyid = *argv;
  }
  *keyid = NULL;

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  err = gpgme_op_receive_keys (ctx, keyids);
  fail_if_err (err);
  impres = gpgme_op_import_result (ctx);
  if (!impres)
    {
      fprintf (stderr, PGM ": no import result returned\n");
      exit (1);
    }
  print_import_result (impres);

  if (verbose)
    {
      gpgme_data_t log;
      char *buf;
      size_t len;

      gpgme_data_new (&log);
      err = gpgme_op_getauditlog (ctx, log, GPGME_AUDITLOG_DIAG);
      fail_if_err (err);
      buf = gpgme_data_release_and_get_mem (log, &len);
      printf ("\nDiagnostic output:\n%.*s\n", (int)len, buf);
      free (buf);
    }

  gpgme_release (ctx);
  return 0;
}

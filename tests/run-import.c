/* pgp-import.c  - Helper to run an import command
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

#include <gpgme.h>

#define PGM "run-import"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FILENAMEs\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --offline        use offline mode\n"
         "  --key-origin     use the specified key origin\n"
         "  --import-options use the specified import options\n"
         "  --url            import from given URLs\n"
         "  -0               URLs are delimited by a nul\n"
         , stderr);
  exit (ex);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  int url_mode = 0;
  int nul_mode = 0;
  gpgme_import_result_t impres;
  gpgme_data_t data;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  char *import_options = NULL;
  char *import_filter = NULL;
  char *key_origin = NULL;
  int offline = 0;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
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
      else if (!strcmp (*argv, "--url"))
        {
          url_mode = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "-0"))
        {
          nul_mode = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--openpgp"))
        {
          protocol = GPGME_PROTOCOL_OpenPGP;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--cms"))
        {
          protocol = GPGME_PROTOCOL_CMS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--import-options"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          import_options = strdup (*argv);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--import-filter"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          import_filter = strdup (*argv);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--key-origin"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          key_origin = strdup (*argv);
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--offline"))
        {
          offline = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (!argc)
    show_usage (1);

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  gpgme_set_offline (ctx, offline);

  if (import_options)
    {
      err = gpgme_set_ctx_flag (ctx, "import-options", import_options);
      fail_if_err (err);
    }
  if (import_filter)
    {
      err = gpgme_set_ctx_flag (ctx, "import-filter", import_filter);
      fail_if_err (err);
    }
  if (key_origin)
    {
      err = gpgme_set_ctx_flag (ctx, "key-origin", key_origin);
      fail_if_err (err);
    }

  for (; argc; argc--, argv++)
    {
      printf ("reading file `%s'\n", *argv);
      err = gpgme_data_new_from_file (&data, *argv, 1);
      fail_if_err (err);

      if (url_mode)
        gpgme_data_set_encoding (data, (nul_mode? GPGME_DATA_ENCODING_URL0
                                        : GPGME_DATA_ENCODING_URL));

      err = gpgme_op_import (ctx, data);
      fail_if_err (err);
      impres = gpgme_op_import_result (ctx);
      if (!impres)
        {
          fprintf (stderr, PGM ": no import result returned\n");
          exit (1);
        }
      print_import_result (impres);

      gpgme_data_release (data);
    }

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

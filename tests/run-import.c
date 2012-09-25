/* pgp-import.c  - Helper to run an import command
   Copyright (C) 2008, 2009 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
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
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (!argc)
    show_usage (1);

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, GPGME_PROTOCOL_OpenPGP);

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

  gpgme_release (ctx);
  return 0;
}

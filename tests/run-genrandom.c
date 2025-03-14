/* run-genrandom.c  - Test tool for the genrandom function
 * Copyright (C) 2025 g10 Code GmbH
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
#include <assert.h>
#include <errno.h>
#include <stdint.h>

#include <gpgme.h>

#define PGM "run-genrandom"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] [LIMIT]\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --zbase32        generate 30 zbase32 characters\n"
         "  --hex            return a hex value in LIMIT mode\n"
         "\n"
         "With LIMIT return a decimal value in the range [0,LIMIT)\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OPENPGP;
  gpgme_random_mode_t mode = 0;
  char buffer[128];
  int hexmode = 0;
  int valuemode = 0;


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
      else if (!strcmp (*argv, "--zbase32"))
        {
          mode = GPGME_RANDOM_MODE_ZBASE32;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--hex"))
        {
          hexmode = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (argc == 1)
    valuemode = 1;
  else if (argc)
    show_usage (1);

  if ((valuemode && mode) || (!valuemode && hexmode))
    show_usage (1);

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);

  if (valuemode)
    {
      size_t limit, value;

      errno = 0;
      limit = strtoul (*argv, NULL, 0);
      if (errno)
        {
          fprintf (stderr, PGM ": error parsing LIMIT arg: %s\n",
                   strerror (errno));
          exit (1);
        }
      if (limit > SIZE_MAX)
        {
          fprintf (stderr, PGM ": error parsing LIMIT arg: %s\n",
                   "too large for size_t");
          exit (1);
        }

      err = gpgme_op_random_value (ctx, limit, &value);
      if (err)
        {
          fprintf (stderr, PGM ": error getting random: %s\n",
                   gpg_strerror (err));
          exit (1);
        }

      if (hexmode)
        printf ("%zx\n", value);
      else
        printf ("%zu\n", value);
    }
  else
    {
      err = gpgme_op_random_bytes (ctx, mode, buffer, sizeof buffer);
      if (err)
        {
          fprintf (stderr, PGM ": error getting random: %s\n",
                   gpg_strerror (err));
          exit (1);
        }

      if (mode == GPGME_RANDOM_MODE_ZBASE32)
        puts (buffer);
      else
        {
          int i;

          for (i=0; i < sizeof buffer; i++)
            {
              if (i && !(i%32))
                putchar ('\n');
              printf ("%02x", ((unsigned char *)buffer)[i]);
            }
          putchar ('\n');
        }
    }

  gpgme_release (ctx);
  return 0;
}

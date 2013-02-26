/* t-version.c - Regression test.
   Copyright (C) 2001, 2004 g10 Code GmbH

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
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gpgme.h>

static int verbose;
static int debug;


int
main (int argc, char **argv)
{
  int ret;
  const char *null_result;
  const char *current_result;
  const char *future_result;

  int last_argc = -1;

  if (argc)
    {
      argc--; argv++;
    }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--help"))
        {
          puts ("usage: ./t-version [options]\n"
                "\n"
                "Options:\n"
                "  --verbose      Show what is going on\n"
                );
          exit (0);
        }
      if (!strcmp (*argv, "--verbose"))
        {
          verbose = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose = debug = 1;
          argc--; argv++;
        }
    }

  null_result = gpgme_check_version (NULL);
  current_result = gpgme_check_version (VERSION);
  future_result = gpgme_check_version (VERSION ".1");

  ret = !(null_result
          && ! strcmp (null_result, VERSION)
          && current_result
          && ! strcmp (current_result, VERSION)
          && ! future_result);

  if (verbose || ret)
    {
      printf ("Version from header: %s (0x%06x)\n",
               GPGME_VERSION, GPGME_VERSION_NUMBER);
      printf ("Version from binary: %s\n", gpgme_check_version (NULL));
      printf ("Copyright blurb ...:%s\n", gpgme_check_version ("\x01\x01"));
    }

  return ret;
}

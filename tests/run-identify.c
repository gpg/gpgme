/* run-identify  - Helper to run the identify command
 * Copyright (C) 2016 g10 Code GmbH
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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
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

#define PGM "run-identify"

#include "run-support.h"


static int verbose;


static const char *
data_type_to_string (gpgme_data_type_t dt)
{
  const char *s = "[?]";

  switch (dt)
    {
    case GPGME_DATA_TYPE_INVALID      : s = "invalid"; break;
    case GPGME_DATA_TYPE_UNKNOWN      : s = "unknown"; break;
    case GPGME_DATA_TYPE_PGP_SIGNED   : s = "PGP-signed"; break;
    case GPGME_DATA_TYPE_PGP_SIGNATURE: s = "PGP-signature"; break;
    case GPGME_DATA_TYPE_PGP_ENCRYPTED: s = "PGP-encrypted"; break;
    case GPGME_DATA_TYPE_PGP_OTHER    : s = "PGP"; break;
    case GPGME_DATA_TYPE_PGP_KEY      : s = "PGP-key"; break;
    case GPGME_DATA_TYPE_CMS_SIGNED   : s = "CMS-signed"; break;
    case GPGME_DATA_TYPE_CMS_ENCRYPTED: s = "CMS-encrypted"; break;
    case GPGME_DATA_TYPE_CMS_OTHER    : s = "CMS"; break;
    case GPGME_DATA_TYPE_X509_CERT    : s = "X.509"; break;
    case GPGME_DATA_TYPE_PKCS12       : s = "PKCS12"; break;
    }
  return s;
}


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FILENAMEs\n\n"
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
  int anyerr = 0;
  gpgme_data_t data;
  gpgme_data_type_t dt;

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
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  for (; argc; argc--, argv++)
    {
      if (verbose)
        printf ("reading file `%s'\n", *argv);
      err = gpgme_data_new_from_file (&data, *argv, 1);
      if (err)
        {
          fprintf (stderr, PGM ": error reading '%s': %s\n",
                   *argv, gpg_strerror (err));
          anyerr = 1;
        }
      else
        {
          dt = gpgme_data_identify (data, 0);
          if (dt == GPGME_DATA_TYPE_INVALID)
            anyerr = 1;
          printf ("%s: %s\n", *argv, data_type_to_string (dt));
          gpgme_data_release (data);
        }
    }

  return anyerr;
}

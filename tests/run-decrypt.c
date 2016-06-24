/* run-decrypt.c  - Helper to perform a verify operation
   Copyright (C) 2009 g10 Code GmbH
                 2016 Intevation GmbH

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

#define PGM "run-decrypt"

#include "run-support.h"


static int verbose;

static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  fprintf (stderr, "status_cb: %s %s\n", keyword, value);
  return 0;
}


static void
print_result (gpgme_decrypt_result_t result)
{
  gpgme_recipient_t recp;
  int count = 0;
  printf ("Original file name: %s\n", nonnull(result->file_name));
  printf ("Wrong key usage: %i\n", result->wrong_key_usage);
  printf ("Unsupported algorithm: %s\n ", nonnull(result->unsupported_algorithm));

  for (recp = result->recipients; recp->next; recp = recp->next)
    {
      printf ("recipient %d\n", count++);
      printf ("  status ....: %s\n", gpgme_strerror (recp->status));
      printf ("  keyid: %s\n", nonnull (recp->keyid));
      printf ("  algo ...: %s\n", gpgme_pubkey_algo_name (recp->pubkey_algo));
    }
}


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FILE\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --status         print status lines from the backend\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  FILE *fp_in = NULL;
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;
  gpgme_decrypt_result_t result;
  int print_status = 0;

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
      else if (!strcmp (*argv, "--status"))
        {
          print_status = 1;
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
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (argc < 1 || argc > 2)
    show_usage (1);

  fp_in = fopen (argv[0], "rb");
  if (!fp_in)
    {
      err = gpgme_error_from_syserror ();
      fprintf (stderr, PGM ": can't open `%s': %s\n",
               argv[0], gpgme_strerror (err));
      exit (1);
    }

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);
  if (print_status)
    {
      gpgme_set_status_cb (ctx, status_cb, NULL);
      gpgme_set_ctx_flag (ctx, "full-status", "1");
    }

  err = gpgme_data_new_from_stream (&in, fp_in);
  if (err)
    {
      fprintf (stderr, PGM ": error allocating data object: %s\n",
               gpgme_strerror (err));
      exit (1);
    }

  err = gpgme_data_new (&out);
  if (err)
    {
      fprintf (stderr, PGM ": error allocating data object: %s\n",
               gpgme_strerror (err));
      exit (1);
    }

  err = gpgme_op_decrypt (ctx, in, out);
  result = gpgme_op_decrypt_result (ctx);
  if (err)
    {
      fprintf (stderr, PGM ": decrypt failed: %s\n", gpgme_strerror (err));
      exit (1);
    }
  if (result) {
    print_result (result);
    print_data (out);
  }

  gpgme_data_release (out);
  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}

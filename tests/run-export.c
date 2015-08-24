/* pgp-export.c  - Helper to run an export command
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

#define PGM "run-export"

#include "run-support.h"


static int verbose;


static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] USERIDS\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --openpgp        use OpenPGP protocol (default)\n"
         "  --cms            use X.509 protocol\n"
         "  --extern         send keys to the keyserver (TAKE CARE!)\n"
         "  --secret         export secret keys instead of public keys\n"
         "  --raw            use PKCS#1 as secret key format\n"
         "  --pkcs12         use PKCS#12 as secret key format\n"
         , stderr);
  exit (ex);
}

int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  gpgme_key_t keyarray[100];
  int keyidx = 0;
  gpgme_data_t out;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_export_mode_t mode = 0;

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
      else if (!strcmp (*argv, "--extern"))
        {
          mode |= GPGME_EXPORT_MODE_EXTERN;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--secret"))
        {
          mode |= GPGME_EXPORT_MODE_SECRET;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--raw"))
        {
          mode |= GPGME_EXPORT_MODE_RAW;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--pkcs12"))
        {
          mode |= GPGME_EXPORT_MODE_PKCS12;
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

  /* Lookup the keys.  */
  err = gpgme_op_keylist_ext_start (ctx, (const char**)argv, 0, 0);
  fail_if_err (err);

  while (!(err = gpgme_op_keylist_next (ctx, &key)))
    {
      printf ("keyid: %s  (fpr: %s)\n",
              key->subkeys?nonnull (key->subkeys->keyid):"?",
              key->subkeys?nonnull (key->subkeys->fpr):"?");

      if (keyidx < DIM (keyarray)-1)
        keyarray[keyidx++] = key;
      else
        {
          fprintf (stderr, PGM": too many keys"
                   "- skipping this key\n");
          gpgme_key_unref (key);
        }
    }
  if (gpgme_err_code (err) != GPG_ERR_EOF)
    fail_if_err (err);
  err = gpgme_op_keylist_end (ctx);
  fail_if_err (err);
  keyarray[keyidx] = NULL;

  result = gpgme_op_keylist_result (ctx);
  if (result->truncated)
    {
      fprintf (stderr, PGM ": key listing unexpectedly truncated\n");
      exit (1);
    }

  /* Now for the actual export.  */
  if ((mode & GPGME_EXPORT_MODE_EXTERN))
    printf ("sending keys to keyserver\n");
  if ((mode & GPGME_EXPORT_MODE_SECRET))
    printf ("exporting secret keys!\n");

  err = gpgme_data_new (&out);
  fail_if_err (err);

  gpgme_set_armor (ctx, 1);
  err = gpgme_op_export_keys (ctx, keyarray, mode,
                              (mode & GPGME_KEYLIST_MODE_EXTERN)? NULL:out);
  fail_if_err (err);

  fflush (NULL);
  if (!(mode & GPGME_KEYLIST_MODE_EXTERN))
    {
      fputs ("Begin Result:\n", stdout);
      print_data (out);
      fputs ("End Result.\n", stdout);
    }

  /* Cleanup.  */
  gpgme_data_release (out);

  for (keyidx=0; keyarray[keyidx]; keyidx++)
    gpgme_key_unref (keyarray[keyidx]);

  gpgme_release (ctx);
  return 0;
}

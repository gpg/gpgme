/* run-keysign.c  - Test tool to sign a key
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
#include <assert.h>

#include <gpgme.h>

#define PGM "run-keysign"

#include "run-support.h"


static int verbose;


static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  fprintf (stderr, "status_cb: %s %s\n", nonnull(keyword), nonnull(value));
  return 0;
}


static unsigned long
parse_expire_string (const char *string)
{
  unsigned long seconds;

  if (!string || !*string || !strcmp (string, "none")
      || !strcmp (string, "never") || !strcmp (string, "-"))
    seconds = 0;
  else if (strspn (string, "01234567890") == strlen (string))
    seconds = strtoul (string, NULL, 10);
  else
    {
      fprintf (stderr, PGM ": invalid value '%s'\n", string);
      exit (1);
    }

  return seconds;
}



static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FPR USERIDS\n\n"
         "Options:\n"
         "  --verbose        run in verbose mode\n"
         "  --status         print status lines from the backend\n"
         "  --loopback       use a loopback pinentry\n"
         "  --signer NAME    use key NAME for signing\n"
         "  --local          create a local signature\n"
         "  --noexpire       force no expiration\n"
         "  --expire EPOCH   expire the signature at EPOCH\n"
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
  const char *signer_string = NULL;
  int print_status = 0;
  int use_loopback = 0;
  const char *userid;
  unsigned int flags = 0;
  unsigned long expire = 0;
  gpgme_key_t thekey;
  int i;
  size_t n;
  char *userid_buffer = NULL;

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
      else if (!strcmp (*argv, "--signer"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          signer_string = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loopback"))
        {
          use_loopback = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--local"))
        {
          flags |= GPGME_KEYSIGN_LOCAL;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--noexpire"))
        {
          flags |= GPGME_KEYSIGN_NOEXPIRE;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--expire"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          expire = parse_expire_string (*argv);
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (!argc)
    show_usage (1);
  userid = argv[0];
  argc--; argv++;

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);
  gpgme_set_armor (ctx, 1);
  if (print_status)
    {
      gpgme_set_status_cb (ctx, status_cb, NULL);
      gpgme_set_ctx_flag (ctx, "full-status", "1");
    }
  if (use_loopback)
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }

  if (signer_string)
    {
      gpgme_key_t akey;

      err = gpgme_get_key (ctx, signer_string, &akey, 1);
      if (err)
        {
          fprintf (stderr, PGM ": error getting signer key '%s': %s\n",
                   signer_string, gpg_strerror (err));
          exit (1);
        }
      err = gpgme_signers_add (ctx, akey);
      if (err)
        {
          fprintf (stderr, PGM ": error adding signer key: %s\n",
                   gpg_strerror (err));
          exit (1);
        }
      gpgme_key_unref (akey);
    }


  err = gpgme_get_key (ctx, userid, &thekey, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error getting key for '%s': %s\n",
               userid, gpg_strerror (err));
      exit (1);
    }

  if (argc > 1)
    {
      /* Several user ids given  */
      for (i=0, n = 0; i < argc; i++)
        n += strlen (argv[1]) + 1;
      n++;
      userid_buffer = malloc (n);
      if (!userid_buffer)
        {
          fprintf (stderr, PGM ": malloc failed: %s\n",
                   gpg_strerror (gpg_error_from_syserror ()));
          exit (1);
        }
      *userid_buffer = 0;
      for (i=0; i < argc; i++)
        {
          strcat (userid_buffer, argv[i]);
          strcat (userid_buffer, "\n");
        }
      userid = userid_buffer;
      flags |= GPGME_KEYSIGN_LFSEP;
    }
  else if (argc)
    {
      /* One user id given  */
      userid = *argv;
    }
  else
    {
      /* No user id given.  */
      userid = NULL;
    }

  err = gpgme_op_keysign (ctx, thekey, userid, expire, flags);
  if (err)
    {
      fprintf (stderr, PGM ": gpgme_op_adduid failed: %s\n",
               gpg_strerror (err));
      exit (1);
    }

  free (userid_buffer);
  gpgme_key_unref (thekey);
  gpgme_release (ctx);
  return 0;
}

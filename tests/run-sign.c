/* run-sign.c  - Helper to perform a sign operation
 * Copyright (C) 2009 g10 Code GmbH
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

#define PGM "run-sign"

#include "run-support.h"


static int verbose;

static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  printf ("status_cb: %s %s\n", keyword, value);
  return 0;
}


static void
print_result (gpgme_sign_result_t result, gpgme_sig_mode_t type)
{
  gpgme_invalid_key_t invkey;
  gpgme_new_signature_t sig;

  (void)type;

  for (invkey = result->invalid_signers; invkey; invkey = invkey->next)
    printf ("Signing key `%s' not used: %s <%s>\n",
            nonnull (invkey->fpr),
            gpg_strerror (invkey->reason), gpg_strsource (invkey->reason));

  for (sig = result->signatures; sig; sig = sig->next)
    {
      printf ("Key fingerprint: %s\n", nonnull (sig->fpr));
      printf ("Signature type : %d\n", sig->type);
      printf ("Public key algo: %d\n", sig->pubkey_algo);
      printf ("Hash algo .....: %d\n", sig->hash_algo);
      printf ("Creation time .: %ld\n", sig->timestamp);
      printf ("Sig class .....: 0x%u\n", sig->sig_class);
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
         "  --uiserver       use the UI server\n"
         "  --loopback       use a loopback pinentry\n"
         "  --key NAME       use key NAME for signing\n"
         "  --sender MBOX    use MBOX as sender address\n"
         "  --include-key-block  use this option with gpg\n"
         "  --clear          create a clear text signature\n"
         "  --detach         create a detached signature\n"
         "  --direct-file-io  pass FILE instead of stream with content of FILE to backend\n"
         "  --archive        create a signed archive with the given file or directory\n"
         "  --directory DIR  switch to directory DIR before creating the archive\n"
         "  --output FILE    write output to FILE instead of stdout\n"
         "  --diagnostics    print diagnostics\n"
         , stderr);
  exit (ex);
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  const char *key_string = NULL;
  const char *directory = NULL;
  const char *output = NULL;
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_sig_mode_t sigmode = GPGME_SIG_MODE_NORMAL;
  gpgme_data_t in, out;
  gpgme_sign_result_t result;
  int print_status = 0;
  int use_loopback = 0;
  int include_key_block = 0;
  int diagnostics = 0;
  int direct_file_io = 0;
  const char *sender = NULL;
  const char *s;

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
      else if (!strcmp (*argv, "--uiserver"))
        {
          protocol = GPGME_PROTOCOL_UISERVER;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--key"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          key_string = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sender"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          sender = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loopback"))
        {
          use_loopback = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--include-key-block"))
        {
          include_key_block = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--clear"))
        {
          sigmode = GPGME_SIG_MODE_CLEAR;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--detach"))
        {
          sigmode = GPGME_SIG_MODE_DETACH;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--direct-file-io"))
        {
          direct_file_io = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--archive"))
        {
          sigmode = GPGME_SIG_MODE_ARCHIVE;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--directory"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          directory = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--output"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          output = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--diagnostics"))
        {
          diagnostics = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (argc != 1)
    show_usage (1);

  if (key_string && protocol == GPGME_PROTOCOL_UISERVER)
    {
      fprintf (stderr, PGM ": ignoring --key in UI-server mode\n");
      key_string = NULL;
    }

  init_gpgme (protocol);

  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_protocol (ctx, protocol);
  gpgme_set_armor (ctx, 1);
  if (print_status)
    gpgme_set_status_cb (ctx, status_cb, NULL);
  if (use_loopback)
    gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);

  if (key_string)
    {
      gpgme_key_t akey;

      err = gpgme_get_key (ctx, key_string, &akey, 1);
      if (err)
        {
          fprintf (stderr, PGM ": get key '%s' failed: %s\n",
                   key_string, gpg_strerror (err));
          exit (1);
        }
      err = gpgme_signers_add (ctx, akey);
      fail_if_err (err);
      gpgme_key_unref (akey);
    }

  if (sender)
    {
      err = gpgme_set_sender (ctx, sender);
      fail_if_err (err);
    }

  if (include_key_block)
    {
      err = gpgme_set_ctx_flag (ctx, "include-key-block", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error setting include-key-block:  %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  if (direct_file_io)
    {
      sigmode |= GPGME_SIG_MODE_FILE;
      err = gpgme_data_new (&in);
      fail_if_err (err);
      err = gpgme_data_set_file_name (in, *argv);
      fail_if_err (err);
    }
  else if (sigmode == GPGME_SIG_MODE_ARCHIVE)
    {
      const char *path = *argv;
      err = gpgme_data_new_from_mem (&in, path, strlen (path), 0);
      fail_if_err (err);
      if (directory)
        {
          err = gpgme_data_set_file_name (in, directory);
          fail_if_err (err);
        }
    }
  else
    {
      err = gpgme_data_new_from_file (&in, *argv, 1);
      if (err)
        {
          fprintf (stderr, PGM ": error reading `%s': %s\n",
                  *argv, gpg_strerror (err));
          exit (1);
        }
    }

  err = gpgme_data_new (&out);
  fail_if_err (err);
  if (output)
    {
      err = gpgme_data_set_file_name (out, output);
      fail_if_err (err);
    }

  err = gpgme_op_sign (ctx, in, out, sigmode);
  result = gpgme_op_sign_result (ctx);

  if (diagnostics)
    {
      gpgme_data_t diag;
      gpgme_error_t diag_err;

      gpgme_data_new (&diag);
      diag_err = gpgme_op_getauditlog (ctx, diag, GPGME_AUDITLOG_DIAG);
      if (diag_err)
        {
          fprintf (stderr, PGM ": getting diagnostics failed: %s\n",
                   gpgme_strerror (diag_err));
        }
      else
        {
          fputs ("Begin Diagnostics:\n", stdout);
          print_data (diag);
          fputs ("End Diagnostics.\n", stdout);
        }
      gpgme_data_release (diag);
    }

  if (result)
    print_result (result, sigmode);
  if (err)
    {
      fprintf (stderr, PGM ": signing failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if ((s = gpgme_get_ctx_flag (ctx, "redraw")) && *s)
    fputs ("Screen redraw suggested\n", stdout);

  if (!output)
    {
      fputs ("Begin Output:\n", stdout);
      print_data (out);
      fputs ("End Output.\n", stdout);
    }
  gpgme_data_release (out);

  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}

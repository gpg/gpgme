/* run-encrypt.c  - Helper to perform an encrypt operation
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

#define PGM "run-encrypt"

#include "run-support.h"


static int verbose;
static int cancel_after_progress;


static char *
xstrdup (const char *string)
{
  char *p = strdup (string);
  if (!p)
    {
      fprintf (stderr, "strdup failed\n");
      exit (2);
    }
  return p;
}


static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  fprintf (stderr, "status_cb: %s %s\n", nonnull(keyword), nonnull(value));
  return 0;
}


static void
progress_cb (void *opaque, const char *what, int type, int current, int total)
{
  static int count;
  gpgme_ctx_t ctx = opaque;
  gpg_error_t err;

  (void)type;

  if (total)
    fprintf (stderr, "progress for '%s' %u%% (%d of %d)\n",
             nonnull (what),
             (unsigned)(((double)current / total) * 100), current, total);
  else
    fprintf (stderr, "progress for '%s' %d\n", nonnull(what), current);
  fflush (stderr);
  count++;
  if (cancel_after_progress && count > cancel_after_progress)
    {
      err = gpgme_cancel_async (ctx);
      if (err)
        fprintf (stderr, "gpgme_cancel failed: %s <%s>\n",
                 gpg_strerror (err), gpg_strsource (err));
      else
        {
          fprintf (stderr, "operation canceled\n");
          cancel_after_progress = 0;
        }
    }
}


static void
print_encrypt_result (gpgme_encrypt_result_t result)
{
  gpgme_invalid_key_t invkey;

  printf ("\nEncryption results\n");
  for (invkey = result->invalid_recipients; invkey; invkey = invkey->next)
    printf ("Encryption key `%s' not used: %s <%s>\n",
            nonnull (invkey->fpr),
            gpg_strerror (invkey->reason), gpg_strsource (invkey->reason));
}


static void
print_sign_result (gpgme_sign_result_t result)
{
  gpgme_invalid_key_t invkey;
  gpgme_new_signature_t sig;

  printf ("\nSigning results\n");
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
         "  --verbose          run in verbose mode\n"
         "  --sign             sign data before encryption\n"
         "  --status           print status lines from the backend\n"
         "  --progress         print progress info\n"
         "  --openpgp          use the OpenPGP protocol (default)\n"
         "  --cms              use the CMS protocol\n"
         "  --uiserver         use the UI server\n"
         "  --loopback         use a loopback pinentry\n"
         "  --key NAME         encrypt to key NAME\n"
         "  --keystring NAMES  encrypt to ';' delimited NAMES\n"
         "  --throw-keyids     use this option\n"
         "  --always-trust     use this option\n"
         "  --no-symkey-cache  disable the use of that cache\n"
         "  --wrap             assume input is valid OpenPGP message\n"
         "  --symmetric        encrypt symmetric (OpenPGP only)\n"
         "  --archive          encrypt given file or directory into an archive\n"
         "  --directory DIR    switch to directory DIR before encrypting into an archive\n"
         "  --output FILE      write output to FILE instead of stdout\n"
         "  --diagnostics      print diagnostics\n"
         "  --cancel N         cancel after N progress lines\n"
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
  gpgme_data_t in, out;
  gpgme_encrypt_result_t encrypt_result;
  gpgme_sign_result_t sign_result;
  int print_status = 0;
  int print_progress = 0;
  int use_loopback = 0;
  char *keyargs[10];
  gpgme_key_t keys[10+1];
  int keycount = 0;
  char *keystring = NULL;
  const char *directory = NULL;
  const char *output = NULL;
  int i;
  gpgme_encrypt_flags_t flags = 0;
  gpgme_off_t offset;
  int no_symkey_cache = 0;
  int diagnostics = 0;
  int sign = 0;

  if (argc)
    { argc--; argv++; }

  if (DIM(keys) != DIM(keyargs)+1)
    abort ();

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
      else if (!strcmp (*argv, "--sign"))
        {
          sign = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--status"))
        {
          print_status = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--progress"))
        {
          print_progress = 1;
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
          if (keycount == DIM (keyargs))
            show_usage (1);
          keyargs[keycount++] = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--keystring"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          keystring = xstrdup (*argv);
          for (i=0; keystring[i]; i++)
            if (keystring[i] == ';')
              keystring[i] = '\n';
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--throw-keyids"))
        {
          flags |= GPGME_ENCRYPT_THROW_KEYIDS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--always-trust"))
        {
          flags |= GPGME_ENCRYPT_ALWAYS_TRUST;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--wrap"))
        {
          flags |= GPGME_ENCRYPT_WRAP;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--loopback"))
        {
          use_loopback = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--symmetric"))
        {
          flags |= GPGME_ENCRYPT_SYMMETRIC;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-symkey-cache"))
        {
          no_symkey_cache = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--archive"))
        {
          flags |= GPGME_ENCRYPT_ARCHIVE;
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
      else if (!strcmp (*argv, "--cancel"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          cancel_after_progress = atoi (*argv);
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);

    }

  if (argc != 1)
    show_usage (1);

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
  if (print_progress || cancel_after_progress)
    gpgme_set_progress_cb (ctx, progress_cb, ctx);
  if (use_loopback)
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }
  if (no_symkey_cache)
    {
      err = gpgme_set_ctx_flag (ctx, "no-symkey-cache", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error setting no-symkey-cache:  %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  for (i=0; i < keycount; i++)
    {
      err = gpgme_get_key (ctx, keyargs[i], &keys[i], 0);
      fail_if_err (err);
    }
  keys[i] = NULL;

  if (flags & GPGME_ENCRYPT_ARCHIVE)
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
      offset = gpgme_data_seek (in, 0, SEEK_END);
      if (offset == (gpgme_off_t)(-1))
        {
          err = gpg_error_from_syserror ();
          fprintf (stderr, PGM ": error seeking `%s': %s\n",
                  *argv, gpg_strerror (err));
          exit (1);
        }
      if (gpgme_data_seek (in, 0, SEEK_SET) == (gpgme_off_t)(-1))
        {
          err = gpg_error_from_syserror ();
          fprintf (stderr, PGM ": error seeking `%s': %s\n",
                  *argv, gpg_strerror (err));
          exit (1);
        }
      {
        char numbuf[50];
        char *p;

        p = numbuf + sizeof numbuf;
        *--p = 0;
        do
          {
            *--p = '0' + (offset % 10);
            offset /= 10;
          }
        while (offset);
        err = gpgme_data_set_flag (in, "size-hint", p);
        if (err)
          {
            fprintf (stderr, PGM ": error setting size-hint for `%s': %s\n",
                    *argv, gpg_strerror (err));
            exit (1);
          }
      }
    }

  err = gpgme_data_new (&out);
  fail_if_err (err);
  if (output)
    {
      err = gpgme_data_set_file_name (out, output);
      fail_if_err (err);
    }

  if (sign)
    err = gpgme_op_encrypt_sign_ext (ctx, keycount ? keys : NULL, keystring,
                                     flags, in, out);
  else
    err = gpgme_op_encrypt_ext (ctx, keycount ? keys : NULL, keystring,
                                flags, in, out);

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

  sign_result = gpgme_op_sign_result (ctx);
  if (sign_result)
    print_sign_result (sign_result);
  encrypt_result = gpgme_op_encrypt_result (ctx);
  if (encrypt_result)
    print_encrypt_result (encrypt_result);
  if (err)
    {
      fprintf (stderr, PGM ": encrypting failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  if (!output)
    {
      fputs ("Begin Output:\n", stdout);
      print_data (out);
      fputs ("End Output.\n", stdout);
    }
  gpgme_data_release (out);

  gpgme_data_release (in);

  for (i=0; i < keycount; i++)
    gpgme_key_unref (keys[i]);
  gpgme_release (ctx);
  free (keystring);
  return 0;
}

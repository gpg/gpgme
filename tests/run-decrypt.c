/* run-decrypt.c  - Helper to perform a verify operation
 * Copyright (C) 2009 g10 Code GmbH
 *               2016 by Bundesamt für Sicherheit in der Informationstechnik
 *               Software engineering by Intevation GmbH
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

  printf ("Original file name .: %s\n", nonnull(result->file_name));
  printf ("Wrong key usage ....: %s\n", result->wrong_key_usage? "yes":"no");
  printf ("Legacy w/o MDC ... .: %s\n", result->legacy_cipher_nomdc?"yes":"no");
  printf ("Compliance de-vs ...: %s\n", result->is_de_vs? "yes":"no");
  printf ("MIME flag ..........: %s\n", result->is_mime? "yes":"no");
  printf ("Unsupported algo ...: %s\n", nonnull(result->unsupported_algorithm));
  printf ("Session key ........: %s\n", nonnull (result->session_key));
  printf ("Symmetric algorithm : %s\n", result->symkey_algo);

  for (recp = result->recipients; recp && recp->next; recp = recp->next)
    {
      printf ("Recipient ...: %d\n", count++);
      printf ("  status ....: %s\n", gpgme_strerror (recp->status));
      printf ("  keyid .....: %s\n", nonnull (recp->keyid));
      printf ("  algo ......: %s\n",
              gpgme_pubkey_algo_name (recp->pubkey_algo));
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
         "  --export-session-key            show the session key\n"
         "  --override-session-key STRING   use STRING as session key\n"
         "  --request-origin STRING         use STRING as request origin\n"
         "  --no-symkey-cache               disable the use of that cache\n"
         "  --ignore-mdc-error              allow decryption of legacy data\n"
         "  --unwrap         remove only the encryption layer\n"
         "  --large-buffers  use large I/O buffer\n"
         "  --sensitive      mark data objects as sensitive\n"
         "  --archive        extract files from an encrypted archive\n"
         "  --directory DIR  extract the files into the directory DIR\n"
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
  gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
  gpgme_decrypt_flags_t flags = 0;
  FILE *fp_in = NULL;
  gpgme_data_t in = NULL;
  gpgme_data_t out = NULL;
  gpgme_decrypt_result_t result;
  int print_status = 0;
  int export_session_key = 0;
  const char *override_session_key = NULL;
  const char *request_origin = NULL;
  const char *directory = NULL;
  int no_symkey_cache = 0;
  int ignore_mdc_error = 0;
  int raw_output = 0;
  int large_buffers = 0;
  int sensitive = 0;
  int diagnostics = 0;

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
      else if (!strcmp (*argv, "--export-session-key"))
        {
          export_session_key = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--override-session-key"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          override_session_key = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--request-origin"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          request_origin = *argv;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-symkey-cache"))
        {
          no_symkey_cache = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--ignore-mdc-error"))
        {
          ignore_mdc_error = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--diagnostics"))
        {
          diagnostics = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--large-buffers"))
        {
          large_buffers = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--sensitive"))
        {
          sensitive = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--unwrap"))
        {
          flags |= GPGME_DECRYPT_UNWRAP;
          raw_output = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--archive"))
        {
          flags |= GPGME_DECRYPT_ARCHIVE;
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
  if (export_session_key)
    {
      err = gpgme_set_ctx_flag (ctx, "export-session-key", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error requesting exported session key: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }
  if (override_session_key)
    {
      err = gpgme_set_ctx_flag (ctx, "override-session-key",
                                override_session_key);
      if (err)
        {
          fprintf (stderr, PGM ": error setting overriding session key: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  if (request_origin)
    {
      err = gpgme_set_ctx_flag (ctx, "request-origin", request_origin);
      if (err)
        {
          fprintf (stderr, PGM ": error setting request_origin: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  if (no_symkey_cache)
    {
      err = gpgme_set_ctx_flag (ctx, "no-symkey-cache", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error setting no-symkey-cache: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  if (ignore_mdc_error)
    {
      err = gpgme_set_ctx_flag (ctx, "ignore-mdc-error", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error setting ignore-mdc-error: %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
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
  if (directory && (flags & GPGME_DECRYPT_ARCHIVE))
    {
      err = gpgme_data_set_file_name (out, directory);
      if (err)
        {
          fprintf (stderr, PGM ": error setting file name (out): %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }
  if (large_buffers)
    {
      err = gpgme_data_set_flag (out, "io-buffer-size", "1000000");
      if (err)
        {
          fprintf (stderr, PGM ": error setting io-buffer-size (out): %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }
  if (sensitive)
    {
      err = gpgme_data_set_flag (out, "sensitive", "1");
      if (err)
        {
          fprintf (stderr, PGM ": error setting sensitive flag (out): %s\n",
                   gpgme_strerror (err));
          exit (1);
        }
    }

  err = gpgme_op_decrypt_ext (ctx, flags, in, out);
  result = gpgme_op_decrypt_result (ctx);

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

  if (err)
    {
      fprintf (stderr, PGM ": decrypt failed: %s\n", gpgme_strerror (err));
      if (result)
        print_result (result);
      exit (1);
    }
  if (result)
    {
      if (!raw_output)
        print_result (result);
      if (!raw_output)
        fputs ("Begin Output:\n", stdout);
      print_data (out);
      if (!raw_output)
        fputs ("End Output.\n", stdout);
    }

  gpgme_data_release (out);
  gpgme_data_release (in);

  gpgme_release (ctx);
  return 0;
}

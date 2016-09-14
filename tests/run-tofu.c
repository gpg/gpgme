/* run-tofu.c  - Test tool for Tofu functions
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

#define PGM "run-tofu"

#include "run-support.h"


static int verbose;


static gpg_error_t
status_cb (void *opaque, const char *keyword, const char *value)
{
  (void)opaque;
  fprintf (stderr, "status_cb: %s %s\n", nonnull(keyword), nonnull(value));
  return 0;
}



static gpgme_tofu_policy_t
parse_policy_string (const char *string)
{
  gpgme_tofu_policy_t policy;

  if (!strcmp (string, "auto"))
    policy = GPGME_TOFU_POLICY_AUTO;
  else if (!strcmp (string, "good"))
    policy = GPGME_TOFU_POLICY_GOOD;
  else if (!strcmp (string, "bad"))
    policy = GPGME_TOFU_POLICY_BAD;
  else if (!strcmp (string, "ask"))
    policy = GPGME_TOFU_POLICY_ASK;
  else if (!strcmp (string, "unknown"))
    policy = GPGME_TOFU_POLICY_UNKNOWN;
  else
    {
      fprintf (stderr, PGM ": invalid policy value '%s'\n", string);
      exit (1);
    }

  return policy;
}



static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] FPR\n\n"
         "Options:\n"
         "  --policy NAME    Set tofu policy for key to NAME\n"
         "  --verbose        run in verbose mode\n"
         "  --status         print status lines from the backend\n"
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
  int print_status = 0;
  gpgme_key_t thekey;
  const char *fpr;
  const char *policystr = NULL;
  gpgme_tofu_policy_t policy;

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
      else if (!strcmp (*argv, "--policy"))
        {
          argc--; argv++;
          if (!argc)
            show_usage (1);
          policystr = *argv;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (argc != 1)
    show_usage (1);
  fpr = argv[0];

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

  err = gpgme_get_key (ctx, fpr, &thekey, 0);
  if (err)
    {
      fprintf (stderr, PGM ": error getting key '%s': %s\n",
               fpr, gpg_strerror (err));
      exit (1);
    }

  if (policystr)
    {
      policy = parse_policy_string (policystr);

      err = gpgme_op_tofu_policy (ctx, thekey, policy);
      if (err)
        {
          fprintf (stderr, PGM ": gpgme_op_tofu_polciy failed: %s\n",
                   gpg_strerror (err));
          exit (1);
        }
    }

  gpgme_key_unref (thekey);
  gpgme_release (ctx);
  return 0;
}

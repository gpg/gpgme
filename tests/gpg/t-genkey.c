/* t-genkey.c - Regression test.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2003, 2004 g10 Code GmbH

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

/* We need to include config.h so that we know whether we are building
   with large file system (LFS) support. */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

#include "t-support.h"


/* True if progress function printed something on the screen.  */
static int progress_called;

static void
progress (void *self, const char *what, int type, int current, int total)
{
  (void)self;

  if (!strcmp (what, "primegen") && !current && !total
      && (type == '.' || type == '+' || type == '!'
	  || type == '^' || type == '<' || type == '>'))
    {
      printf ("%c", type);
      fflush (stdout);
      progress_called = 1;
    }
  else
    {
      fprintf (stderr, "unknown progress `%s' %d %d %d\n", what, type,
	       current, total);
      exit (1);
    }
}


int
main (int argc, char **argv)
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  const char *parms = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: DSA\n"
    "Key-Length: 1024\n"
    "Subkey-Type: ELG-E\n"
    "Subkey-Length: 1024\n"
    "Name-Real: Joe Tester\n"
    "Name-Comment: (pp=abc)\n"
    "Name-Email: joe@foo.bar\n"
    "Expire-Date: 0\n"
    "Passphrase: abc\n"
    "</GnupgKeyParms>\n";
  gpgme_genkey_result_t result;

  (void)argc;
  (void)argv;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);

  err = gpgme_new (&ctx);
  fail_if_err (err);

  gpgme_set_progress_cb (ctx, progress, NULL);

  err = gpgme_op_genkey (ctx, parms, NULL, NULL);
  fail_if_err (err);

  result = gpgme_op_genkey_result (ctx);
  if (!result)
    {
      fprintf (stderr, "%s:%d: gpgme_op_genkey_result returns NULL\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (progress_called)
    printf ("\n");

  printf ("Generated key: %s (%s)\n", result->fpr ? result->fpr : "none",
	  result->primary ? (result->sub ? "primary, sub" : "primary")
	  : (result->sub ? "sub" : "none"));

  if (result->fpr && strlen (result->fpr) != 40)
    {
      fprintf (stderr, "%s:%d: generated key has unexpected fingerprint\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (!result->primary)
    {
      fprintf (stderr, "%s:%d: primary key was not generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  if (!result->sub)
    {
      fprintf (stderr, "%s:%d: sub key was not generated\n",
	       __FILE__, __LINE__);
      exit (1);
    }
  gpgme_release (ctx);
  return 0;
}

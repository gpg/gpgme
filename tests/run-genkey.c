/* run-genkey.c  - Test tool to perform key generation
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

#define PGM "run-genkey"

#include "run-support.h"


static int verbose;


/* Tokenize STRING using the set of delimiters in DELIM.  Leading
 * spaces and tabs are removed from all tokens.  The caller must free
 * the result.
 *
 * Returns: A malloced and NULL delimited array with the tokens.  On
 *          memory error NULL is returned and ERRNO is set.
 */
static char **
strtokenize (const char *string, const char *delim)
{
  const char *s;
  size_t fields;
  size_t bytes, n;
  char *buffer;
  char *p, *px, *pend;
  char **result;

  /* Count the number of fields.  */
  for (fields = 1, s = strpbrk (string, delim); s; s = strpbrk (s + 1, delim))
    fields++;
  fields++; /* Add one for the terminating NULL.  */

  /* Allocate an array for all fields, a terminating NULL, and space
     for a copy of the string.  */
  bytes = fields * sizeof *result;
  if (bytes / sizeof *result != fields)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  n = strlen (string) + 1;
  bytes += n;
  if (bytes < n)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  result = malloc (bytes);
  if (!result)
    return NULL;
  buffer = (char*)(result + fields);

  /* Copy and parse the string.  */
  strcpy (buffer, string);
  for (n = 0, p = buffer; (pend = strpbrk (p, delim)); p = pend + 1)
    {
      *pend = 0;
      while (*p == ' ' || *p == '\t')
        p++;
      for (px = pend - 1; px >= p && (*px == ' ' || *px == '\t'); px--)
        *px = 0;
      result[n++] = p;
    }
  while (*p == ' ' || *p == '\t')
    p++;
  for (px = p + strlen (p) - 1; px >= p && (*px == ' ' || *px == '\t'); px--)
    *px = 0;
  result[n++] = p;
  result[n] = NULL;

  assert ((char*)(result + n + 1) == buffer);

  return result;
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
  (void)opaque;
  (void)type;

  if (total)
    fprintf (stderr, "progress for '%s' %u%% (%d of %d)\n",
             nonnull (what),
             (unsigned)(((double)current / total) * 100), current, total);
  else
    fprintf (stderr, "progress for '%s' %d\n", nonnull(what), current);
  fflush (stderr);
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


/* Parse a usage string and return flags for gpgme_op_createkey.  */
static unsigned int
parse_usage_string (const char *string)
{
  gpg_error_t err;
  char **tokens = NULL;
  const char *s;
  int i;
  unsigned int flags = 0;

  tokens = strtokenize (string, " \t,");
  if (!tokens)
    {
      err = gpg_error_from_syserror ();
      fprintf (stderr, PGM": strtokenize failed: %s\n", gpg_strerror (err));
      exit (1);
    }

  for (i=0; (s = tokens[i]); i++)
    {
      if (!*s)
        ;
      else if (!strcmp (s, "default"))
        ;
      else if (!strcmp (s, "sign"))
        flags |= GPGME_CREATE_SIGN;
      else if (!strcmp (s, "encr"))
        flags |= GPGME_CREATE_ENCR;
      else if (!strcmp (s, "cert"))
        flags |= GPGME_CREATE_CERT;
      else if (!strcmp (s, "auth"))
        flags |= GPGME_CREATE_AUTH;
      else
        {
          free (tokens);
          fprintf (stderr, PGM": invalid value '%s': %s\n",
                   string, "bad usage");
          exit (1);
        }
    }

  free (tokens);
  return flags;
}



static int
show_usage (int ex)
{
  fputs ("usage: " PGM " [options] ARGS\n"
         "         args: USERID [ALGO [USAGE [EXPIRESECONDS]]]\n"
         "   for addkey: FPR    [ALGO [USAGE [EXPIRESECONDS]]]\n"
         "   for adduid: FPR    USERID\n"
         "   for revuid: FPR    USERID\n"
         "Options:\n"
         "  --addkey         add a subkey to the key with FPR\n"
         "  --adduid         add a user id to the key with FPR\n"
         "  --revuid         Revoke a user id from the key with FPR\n"
         "  --verbose        run in verbose mode\n"
         "  --status         print status lines from the backend\n"
         "  --progress       print progress info\n"
         "  --openpgp        use the OpenPGP protocol (default)\n"
         "  --cms            use the CMS protocol\n"
         "  --loopback       use a loopback pinentry\n"
         "  --unprotected    do not use a passphrase\n"
         "  --force          do not check for a duplicated user id\n"
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
  int print_progress = 0;
  int use_loopback = 0;
  int addkey = 0;
  int adduid = 0;
  int revuid = 0;
  const char *userid;
  const char *algo = NULL;
  const char *newuserid = NULL;
  unsigned int flags = 0;
  unsigned long expire = 0;
  gpgme_genkey_result_t result;

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
      else if (!strcmp (*argv, "--addkey"))
        {
          addkey = 1;
          adduid = 0;
          revuid = 0;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--adduid"))
        {
          addkey = 0;
          adduid = 1;
          revuid = 0;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--revuid"))
        {
          addkey = 0;
          adduid = 0;
          revuid = 1;
          argc--; argv++;
        }
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
      else if (!strcmp (*argv, "--loopback"))
        {
          use_loopback = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--unprotected"))
        {
          flags |= GPGME_CREATE_NOPASSWD;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--force"))
        {
          flags |= GPGME_CREATE_FORCE;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        show_usage (1);
    }

  if (adduid || revuid)
    {
      if (argc != 2)
        show_usage (1);
      userid = argv[0];
      newuserid = argv[1];
    }
  else
    {
      if (!argc || argc > 4)
        show_usage (1);
      userid = argv[0];
      if (argc > 1)
        algo = argv[1];
      if (argc > 2)
        flags |= parse_usage_string (argv[2]);
      if (argc > 3)
        expire = parse_expire_string (argv[3]);
    }

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
  if (print_progress)
    gpgme_set_progress_cb (ctx, progress_cb, NULL);
  if (use_loopback)
    {
      gpgme_set_pinentry_mode (ctx, GPGME_PINENTRY_MODE_LOOPBACK);
      gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
    }

  if (addkey || adduid || revuid)
    {
      gpgme_key_t akey;

      err = gpgme_get_key (ctx, userid, &akey, 1);
      if (err)
        {
          fprintf (stderr, PGM ": error getting secret key for '%s': %s\n",
                   userid, gpg_strerror (err));
          exit (1);
        }

      if (addkey)
        {
          err = gpgme_op_createsubkey (ctx, akey, algo, 0, expire, flags);
          if (err)
            {
              fprintf (stderr, PGM ": gpgme_op_createsubkey failed: %s\n",
                       gpg_strerror (err));
              exit (1);
            }
        }
      else if (adduid)
        {
          err = gpgme_op_adduid (ctx, akey, newuserid, flags);
          if (err)
            {
              fprintf (stderr, PGM ": gpgme_op_adduid failed: %s\n",
                       gpg_strerror (err));
              exit (1);
            }
        }
      else if (revuid)
        {
          err = gpgme_op_revuid (ctx, akey, newuserid, flags);
          if (err)
            {
              fprintf (stderr, PGM ": gpgme_op_revuid failed: %s\n",
                       gpg_strerror (err));
              exit (1);
            }
        }
      gpgme_key_unref (akey);
    }
  else
    {
      err = gpgme_op_createkey (ctx, userid, algo, 0, expire, NULL, flags);
      if (err)
        {
          fprintf (stderr, PGM ": gpgme_op_createkey failed: %s\n",
                   gpg_strerror (err));
          exit (1);
        }
    }

  result = gpgme_op_genkey_result (ctx);
  if (!result)
    {
      fprintf (stderr, PGM": gpgme_op_genkey_result returned NULL\n");
      exit (1);
    }

  printf ("Generated key: %s (%s)\n",
          result->fpr ? result->fpr : "none",
	  result->primary ? (result->sub ? "primary, sub" : "primary")
          /**/     	  : (result->sub ? "sub" : "none"));

  if (result->fpr && strlen (result->fpr) < 40)
    fprintf (stderr, PGM": generated key has unexpected fingerprint\n");
  if (!result->primary)
    fprintf (stderr, PGM": primary key was not generated\n");
  if (!result->sub)
    fprintf (stderr, PGM": sub key was not generated\n");
  if (!result->uid)
    fprintf (stderr, PGM": uid was not generated\n");

  gpgme_release (ctx);
  return 0;
}

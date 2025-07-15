/* gnupg-key-manage.c - Managment tool for keys
 * Copyright (C) 2025 g10 Code GmbH
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

/* This tool provides some specialized commands for key management
 * tasks.  Although this could be done using scripting, it avoids
 * problems maintaining such scripts for Unix and Windows.
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/stat.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif


#define GPGRT_ENABLE_ES_MACROS 1
#define GPGRT_ENABLE_LOG_MACROS 1
#define GPGRT_ENABLE_ARGPARSE_MACROS 1
#include <gpgme.h>


static struct
{
  int verbose;   /* The verbosity level.  */
  int debug;     /* True if debug mode is active.  */
  int pgp;       /* Select PGP keys.  */
  int x509;      /* Select X.509 keys.  */
  int all;       /* Work on all keys in the keyring.  */
  int dryrun;    /* No actual changes.  */
  int with_secret; /* Also process secret keys.  */
} opt;


/* An object to store keys in an array.  */
struct keyarray_s
{
  size_t size;
  size_t used;
  gpgme_key_t *keys; /* Allocated with SIZE elements.  */
};
typedef struct keyarray_s *keyarray_t;




/*
 * Helper macros and functions
 */

#define xtrystrdup(a)  gpgrt_strdup ((a))
#define xcalloc(a,b) ({                         \
      void *_r = gpgrt_calloc ((a), (b));       \
      if (!_r)                                  \
        xoutofcore ("calloc");                  \
      _r; })
#define xstrdup(a) ({                           \
      char *_r = gpgrt_strdup ((a));            \
      if (!_r)                                  \
        xoutofcore ("strdup");                  \
      _r; })
#define xstrconcat(a, ...) ({                           \
      char *_r = gpgrt_strconcat ((a), __VA_ARGS__);    \
      if (!_r)                                          \
        xoutofcore ("strconcat");                       \
      _r; })
#define xfree(a) gpgrt_free ((a))

#define xtrymalloc(a)  gpgrt_malloc ((a))
#define xmalloc(a) ({                           \
      void *_r = gpgrt_malloc ((a));            \
      if (!_r)                                  \
        xoutofcore ("malloc");                  \
      _r; })
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')

static void
xoutofcore (const char *type)
{
  gpg_error_t err = gpg_error_from_syserror ();
  log_error ("%s failed: %s\n", type, gpg_strerror (err));
  exit (2);
}


/* Note that this is a copy from ../src/json-utils.c */
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


/* Return a new context object or die.  */
static gpgme_ctx_t
create_context (void)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;

  err = gpgme_new (&ctx);
  if (err)
    {
      log_error ("error creating a new context: %s\n", gpg_strerror (err));
      exit (2);
    }
  return ctx;
}


/* Create a new key array object or die.  */
static keyarray_t
create_keyarray (void)
{
  keyarray_t array;
  array = xcalloc (1, sizeof *array);
  return array;
}

/* Release the array object and all keys.  */
static void
free_keyarray (keyarray_t array)
{
  size_t n;

  if (!array)
    return;
  for (n=0; n < array->used; n++)
    gpgme_key_unref (array->keys[n]);
  xfree (array->keys);
  array->keys = 0;
  array->size = 0;
  array->used = 0;
  xfree (array);
}

/* Add KEY to the ARRAY.  Enlarge array as needed.  A new ref is taken
 * for the key. */
static void
add_to_keyarray (keyarray_t array, gpgme_key_t key)
{
  if (!array->keys || array->used == array->size)
    {
      size_t incr = 128;
      void *p = gpgrt_reallocarray (array->keys, array->size,
                                    array->size+incr, sizeof *array->keys);
      if (!p)
        xoutofcore ("reallocarray");
      array->keys = p;
      array->size += incr;
    }
  gpgme_key_ref (key);
  array->keys[array->used++] = key;
}




/*
 * The identify command.
 */
static gpg_error_t
cmd_identify (const char *fname)
{
  gpg_error_t err;
  estream_t fp;
  gpgme_data_t data;
  gpgme_data_type_t dt;

  if (fname)
    {
      fp = es_fopen (fname, "rb");
      if (!fp)
        {
          err = gpg_error_from_syserror ();
          log_error ("can't open '%s': %s\n", fname, gpg_strerror (err));
          return err;
        }
      err = gpgme_data_new_from_estream (&data, fp);
    }
  else
    {
      char *buffer;
      int n;

      fp = NULL;
      es_set_binary (es_stdin);

      /* Urgs: gpgme_data_identify does a seek and that fails for stdin.  */
      buffer = xmalloc (2048+1);
      n = es_fread (buffer, 1, 2048, es_stdin);
      if (n < 0 || es_ferror (es_stdin))
        {
          err = gpg_error_from_syserror ();
          log_error ("error reading '%s': %s\n", "[stdin]", gpg_strerror (err));
          xfree (buffer);
          return err;
        }
      buffer[n] = 0;
      err = gpgme_data_new_from_mem (&data, buffer, n, 1);
      xfree (buffer);
    }

  if (err)
    {
      log_error ("error creating data object: %s\n", gpg_strerror (err));
      return err;
    }

  dt = gpgme_data_identify (data, 0);
  if (fname && dt == GPGME_DATA_TYPE_UNKNOWN
      && gpgme_data_seek (data, 0, SEEK_SET) != (gpgme_off_t)(-1))
    {
      /* This might be a PGP or PEM file with a long ascii lead in.
       * Search for the dashes and try again.  We do this only if a
       * file was given to complications with the already ready
       * buffered stdin.  */
      /* FIXME: We need a buffered read for gpgme_data-t.  */
    }

  if (dt == GPGME_DATA_TYPE_INVALID)
    log_error ("%s: error identifying data\n", fname? fname:"-");
  if (fname)
    es_printf ("%s: ", fname);
  es_printf ("%s\n", data_type_to_string (dt));
  gpgme_data_release (data);
  es_fclose (fp);
  return 0;
}



/*
 * The delete-expired command.
 *
 * Walk over all keys and delete those which have expired.  By default
 * only X.509 keys are considered because PGP keys can be prolonged.
 * To work on PGP keys the option --pgp is required.  */
static gpg_error_t
cmd_delexpired (const char *pattern)
{
  gpg_error_t err, firsterr;
  gpgme_ctx_t ctx = create_context ();
  keyarray_t expiredkeys = create_keyarray ();
  gpgme_key_t key = NULL;
  gpgme_protocol_t proto;
  const char *protostr;
  size_t n;

  /* This command defaults to X.509. */
  proto = opt.pgp? GPGME_PROTOCOL_OPENPGP:GPGME_PROTOCOL_CMS;
  protostr = (proto == GPGME_PROTOCOL_OPENPGP)? "(pgp)":"(x.509)";

  err = gpgme_set_protocol (ctx, proto);
  if (err)
    {
      log_error ("error setting the protocol: %s\n", gpg_strerror (err));
      goto leave;
    }
  err = gpgme_set_keylist_mode (ctx, GPGME_KEYLIST_MODE_LOCAL);
  if (err)
    {
      log_error ("error setting setting the listing mode: %s\n",
                 gpg_strerror (err));
      goto leave;
    }
  gpgme_set_offline (ctx, 1);

  err = gpgme_op_keylist_start (ctx, pattern, 0);
  if (err)
    {
      if (pattern)
        log_error ("error listing keys with pattern '%s': %s\n",
                   pattern, gpg_strerror (err));
      else
        log_error ("error listing all keys: %s\n", gpg_strerror (err));
      goto leave;
    }

  for (;;)
    {
      gpgme_key_unref (key);
      err = gpgme_op_keylist_next (ctx, &key);
      if (err)
        break;

      if (!key->subkeys)
        {
          log_error ("internal error: subkey object missing\n");
          continue;
        }
      if (!key->expired)
        continue;
      if (key->secret && !opt.with_secret)
        {
          if (opt.verbose)
            log_info ("key %s %s with secret part skipped\n",
                      key->subkeys->fpr, protostr);
          continue;
        }
      if (opt.verbose || opt.dryrun)
        log_info ("key %s %s has expired\n", key->subkeys->fpr, protostr);
      add_to_keyarray (expiredkeys, key);
    }
  if (gpgme_err_code (err) != GPG_ERR_EOF)
    {
      log_error ("error listing keys: %s\n", gpg_strerror (err));
      goto leave;
    }
  err = gpgme_op_keylist_end (ctx);
  if (err)
    {
      log_error ("error finishing the key listing: %s\n", gpg_strerror (err));
      goto leave;
    }

  if (opt.verbose)
    log_info ("number of keys to delete: %zu\n", expiredkeys->used);
  if (opt.dryrun)
    {
      log_info ("no keys deleted due to option --dry-run\n");
      goto leave;
    }

  firsterr = 0;
  for (n=0; n < expiredkeys->used; n++)
    {
      err = gpgme_op_delete_ext (ctx, expiredkeys->keys[n], 0);
      if (err)
        {
          if (!firsterr)
            firsterr = err;
          log_error ("error deleting key %s %s: %s\n",
                     expiredkeys->keys[n]->subkeys->fpr, protostr,
                     gpg_strerror (err));
        }
      else if (opt.verbose)
        log_error ("key %s %s deleted\n",
                   expiredkeys->keys[n]->subkeys->fpr, protostr);
    }
  if (firsterr)
    err = firsterr;

 leave:
  free_keyarray (expiredkeys);
  gpgme_key_unref (key);
  gpgme_release (ctx);
  return err;
}




static const char *
my_strusage( int level )
{
  const char *p;

  switch (level)
    {
    case  9: p = "LGPL-2.1-or-later"; break;
    case 11: p = "gnupg-key-manage"; break;
    case 13: p = PACKAGE_VERSION; break;
    case 14: p = "Copyright (C) 2025 g10 Code GmbH"; break;
    case 19: p = "Please report bugs to <" PACKAGE_BUGREPORT ">.\n"; break;
    case 1:
    case 40:
      p = "Usage: gnupg-key-manage COMMAND [OPTIONS]";
      break;
    case 41:
      p = ("Syntax: gnupg-key-manage COMMAND [OPTIONS]\n\n"
           "A fine selection of commands for common key management tasks.");
      break;
    default: p = NULL; break;
    }
  return p;
}


int
main (int argc, char *argv[])
{
  enum { CMD_DEFAULT     = 0,
         CMD_IDENTIFY    = 500,
         CMD_DELEXPIRED,
         CMD_LIBVERSION
  } cmd = CMD_DEFAULT;
  enum {
    OPT_DRYRUN = 'n',
    OPT_VERBOSE = 'v',
    OPT_DEBUG = 600,
    OPT_PGP,
    OPT_X509,
    OPT_WITH_SECRET,
    OPT_ALL
  };

  static gpgrt_opt_t opts[] = {
    ARGPARSE_header (NULL, "Commands"),
    ARGPARSE_c  (CMD_IDENTIFY,    "identify",    "Identify the input"),
    ARGPARSE_c  (CMD_DELEXPIRED,  "delete-expired",
                 "Delete expired keys (defaults to X.509)"),
    ARGPARSE_c  (CMD_LIBVERSION,  "lib-version", "@"),

    ARGPARSE_header (NULL, "Options"),
    ARGPARSE_s_n(OPT_PGP,     "pgp",      "Select PGP keys"),
    ARGPARSE_s_n(OPT_X509,    "x509",     "Select X.509 keys"),
    ARGPARSE_s_n(OPT_ALL,     "all",      "Work on the entire keyring"),
    ARGPARSE_s_n(OPT_WITH_SECRET, "with-secret",
                                          "Work also on secret keys"),

    ARGPARSE_s_n(OPT_DRYRUN,  "dry-run",  "Print only what would be done"),
    ARGPARSE_s_n(OPT_VERBOSE,  "verbose",     "verbose mode"),
    ARGPARSE_s_n(OPT_DEBUG,    "debug",       "enable debug output"),

    ARGPARSE_end()
  };
  gpgrt_argparse_t pargs = { &argc, &argv};
  int i;

  gpgrt_set_strusage (my_strusage);
  /* We disable logging enabled via a registry key.  */
  log_set_prefix (gpgrt_strusage (11), (GPGRT_LOG_WITH_PREFIX
                                        |GPGRT_LOG_NO_REGISTRY));

#ifdef HAVE_SETLOCALE
  setlocale (LC_ALL, "");
#endif
  gpgme_check_version (NULL);
#ifdef LC_CTYPE
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#endif
#ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

#if GPGRT_VERSION_NUMBER >= 0x013000 /* >= 1.48 */
  pargs.flags |= ARGPARSE_FLAG_COMMAND;
#endif
  while (gpgrt_argparse (NULL, &pargs, opts))
    {
      switch (pargs.r_opt)
        {
        case CMD_IDENTIFY:
        case CMD_DELEXPIRED:
        case CMD_LIBVERSION:
          cmd = pargs.r_opt;
          break;

        case OPT_VERBOSE: opt.verbose++; break;
        case OPT_DEBUG: opt.debug = 1; break;
        case OPT_PGP:   opt.pgp = 1; break;
        case OPT_X509:  opt.x509 = 1; break;
        case OPT_WITH_SECRET: opt.with_secret = 1; break;
        case OPT_ALL:   opt.all = 1; break;
        case OPT_DRYRUN: opt.dryrun = 1; break;

        default:
          pargs.err = ARGPARSE_PRINT_ERROR;
	  break;
        }
    }
  gpgrt_argparse (NULL, &pargs, NULL);

  if (opt.pgp && opt.x509)
    {
      log_error ("error: Only one protocol may be specified\n");
      exit (2);
    }


  switch (cmd)
    {
    case CMD_DEFAULT:
      log_info ("Please use the \"help\" command for a list commands\n");
      break;

    case CMD_IDENTIFY:
      if (!argc || !strcmp (*argv, "-"))
        cmd_identify (NULL); /* read from stdin */
      else
        {
          for (i=0; i < argc; i++)
            cmd_identify (argv[i]);
        }
      break;

    case CMD_DELEXPIRED:
      if (!argc && opt.all)
        cmd_delexpired (NULL);
      else if (!argc)
        log_error ("error: option --all is required to work on"
                   " the entire keyring\n");
      else
        {
          for (i=0; i < argc; i++)
            cmd_delexpired (argv[i]);
        }
      break;

    case CMD_LIBVERSION:
      es_printf ("Version from header: %s (0x%06x)\n",
                 GPGME_VERSION, GPGME_VERSION_NUMBER);
      es_printf ("Version from binary: %s\n", gpgme_check_version (NULL));
      es_printf ("Copyright blurb ...:%s\n", gpgme_check_version ("\x01\x01"));
      break;
    }

  if (opt.debug)
    log_debug ("ready\n");

  return 0;
}

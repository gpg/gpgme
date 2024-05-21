/* run-support.h - Helper routines for run-* test programs.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2009 g10 Code GmbH
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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <locale.h>

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <gpgme.h>

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, PGM": file %s line %d: <%s> %s\n",	\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err));			\
          exit (1);						\
        }							\
    }								\
  while (0)


#define fail_with_syserr()			         	\
  do								\
    {								\
      gpg_error_t _err = gpgme_err_code_from_errno (errno);	\
      fprintf (stderr, PGM": file %s line %d: <%s> %s\n",	\
               __FILE__, __LINE__, gpgme_strsource (_err),	\
              gpgme_strerror (_err));			        \
      exit (1);						        \
    }								\
  while (0)


static const char *
nonnull (const char *s)
{
  return s? s :"[none]";
}


void
print_data (gpgme_data_t dh)
{
#define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;

  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    fail_if_err (gpgme_err_code_from_errno (errno));
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (gpgme_err_code_from_errno (errno));
}


gpgme_error_t
passphrase_cb (void *opaque, const char *uid_hint, const char *passphrase_info,
	       int last_was_bad, int fd)
{
  int res;
  char pass[] = "abc\n";
  int passlen = strlen (pass);
  int off = 0;

  (void)opaque;
  (void)uid_hint;
  (void)passphrase_info;
  (void)last_was_bad;

  do
    {
      res = gpgme_io_write (fd, &pass[off], passlen - off);
      if (res > 0)
	off += res;
    }
  while (res > 0 && off != passlen);

  return off == passlen ? 0 : gpgme_error_from_errno (errno);
}


char *
make_filename (const char *fname)
{
  const char *srcdir = getenv ("srcdir");
  char *buf;

  if (!srcdir)
    srcdir = ".";
  buf = malloc (strlen(srcdir) + strlen(fname) + 2);
  if (!buf)
    {
      fprintf (stderr, "%s:%d: could not allocate string: %s\n",
	       __FILE__, __LINE__, strerror (errno));
      exit (8);
    }
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}


void
init_gpgme_basic (void)
{
  gpgme_check_version (NULL);
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
}


void
init_gpgme (gpgme_protocol_t proto)
{
  gpg_error_t err;

  init_gpgme_basic ();
  err = gpgme_engine_check_version (proto);
  fail_if_err (err);
}


void
print_import_result (gpgme_import_result_t r)
{
  gpgme_import_status_t st;

  for (st=r->imports; st; st = st->next)
    {
      printf ("  fpr: %s err: %d (%s) status:", nonnull (st->fpr),
              st->result, gpgme_strerror (st->result));
      if (st->status & GPGME_IMPORT_NEW)
        fputs (" new", stdout);
      if (st->status & GPGME_IMPORT_UID)
        fputs (" uid", stdout);
      if (st->status & GPGME_IMPORT_SIG)
        fputs (" sig", stdout);
      if (st->status & GPGME_IMPORT_SUBKEY)
        fputs (" subkey", stdout);
      if (st->status & GPGME_IMPORT_SECRET)
        fputs (" secret", stdout);
      putchar ('\n');
    }
  printf ("key import summary:\n"
          "        considered: %d\n"
          "        no user id: %d\n"
          "          imported: %d\n"
          "      imported_rsa: %d\n"
          "         unchanged: %d\n"
          "      new user ids: %d\n"
          "       new subkeys: %d\n"
          "    new signatures: %d\n"
          "   new revocations: %d\n"
          "       secret read: %d\n"
          "   secret imported: %d\n"
          "  secret unchanged: %d\n"
          "  skipped new keys: %d\n"
          "      not imported: %d\n"
          "   skipped v3 keys: %d\n",
          r->considered,
          r->no_user_id,
          r->imported,
          r->imported_rsa,
          r->unchanged,
          r->new_user_ids,
          r->new_sub_keys,
          r->new_signatures,
          r->new_revocations,
          r->secret_read,
          r->secret_imported,
          r->secret_unchanged,
          r->skipped_new_keys,
          r->not_imported,
          r->skipped_v3_keys);
}

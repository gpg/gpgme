/* t-support.h - Helper routines for regression tests.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
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
#include <string.h>

#include <gpgme.h>

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s (%d.%d)\n",        	\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err),                        \
                   gpgme_err_source (err), gpgme_err_code (err)); \
          exit (1);						\
        }							\
    }								\
  while (0)


#ifdef GPGRT_HAVE_MACRO_FUNCTION
void GPGRT_ATTR_NORETURN
_test (const char *expr, const char *file, int line,
       const char *func)
{
  fprintf (stderr, "Test \"%s\" in %s failed (%s:%d)\n",
           expr, func, file, line);
  exit (1);
}
# define test(expr)                                             \
  ((expr)                                                       \
   ? (void) 0                                                   \
   : _test (#expr, __FILE__, __LINE__, __FUNCTION__))
#else /*!GPGRT_HAVE_MACRO_FUNCTION*/
void
_test (const char *expr, const char *file, int line)
{
  fprintf (stderr, "Test \"%s\" failed (%s:%d)\n",
           expr, file, line);
  exit (1);
}
# define test(expr)                                             \
  ((expr)                                                       \
   ? (void) 0                                                   \
   : _test (#expr, __FILE__, __LINE__))
#endif /*!GPGRT_HAVE_MACRO_FUNCTION*/


int
safe_strcmp (const char *s1, const char *s2)
{
  return s1 ? (s2 ? strcmp (s1, s2) : 1)
            : (s2 ? -1 : 0);
}


const char *
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
    fail_if_err (gpgme_error_from_errno (errno));
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    fail_if_err (gpgme_error_from_errno (errno));
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
    exit (8);
  strcpy (buf, srcdir);
  strcat (buf, "/");
  strcat (buf, fname);
  return buf;
}


void
init_gpgme (gpgme_protocol_t proto)
{
  gpgme_error_t err;

  gpgme_check_version (NULL);
#ifndef HAVE_W32_SYSTEM
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  err = gpgme_engine_check_version (proto);
  fail_if_err (err);
}


/* Return true if the gpg engine's version is at least REQ_VERSION.  */
int
have_gpgsm_version (const char *req_version)
{
  gpgme_engine_info_t engine_info;
  init_gpgme (GPGME_PROTOCOL_CMS);

  fail_if_err (gpgme_get_engine_info (&engine_info));
  for (; engine_info; engine_info = engine_info->next)
    if (engine_info->protocol == GPGME_PROTOCOL_CMS)
      break;

  test (engine_info);

  return gpgrt_cmp_version (engine_info->version, req_version, 3) >= 0;
}

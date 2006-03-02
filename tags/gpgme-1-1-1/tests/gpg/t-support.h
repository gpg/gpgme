/* t-support.h - Helper routines for regression tests.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

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

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <locale.h>

#include <gpgme.h>

#ifndef DIM
#define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif

#define fail_if_err(err)					\
  do								\
    {								\
      if (err)							\
        {							\
          fprintf (stderr, "%s:%d: %s: %s\n",			\
                   __FILE__, __LINE__, gpgme_strsource (err),	\
		   gpgme_strerror (err));			\
          exit (1);						\
        }							\
    }								\
  while (0)


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
  write (fd, "abc\n", 4);
  return 0;
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
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  err = gpgme_engine_check_version (proto);
  fail_if_err (err);
}

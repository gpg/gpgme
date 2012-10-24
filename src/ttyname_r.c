/* ttyname_r.c - A ttyname_r() replacement.
   Copyright (C) 2003, 2004, 2012 g10 Code GmbH

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif


#if !HAVE_TTYNAME_R && defined(__GNUC__)
# warning ttyname is not thread-safe, and ttyname_r is missing
#endif

/* For Android we force the use of our replacement code.  */
#if HAVE_ANDROID_SYSTEM
# undef HAVE_TTYNAME_R
#endif


int
_gpgme_ttyname_r (int fd, char *buf, size_t buflen)
{
#if HAVE_TTYNAME_R
# if HAVE_BROKEN_TTYNAME_R
   /* Solaris fails if BUFLEN is less than 128. OSF/1 5.1 completely
      ignores BUFLEN.  We use a large buffer to woraround this.  */
  {
    char largebuf[512];
    size_t namelen;
    int rc;

#  if HAVE_POSIXDECL_TTYNAME_R
    if (buflen < sizeof (largebuf))
      {
        rc = ttyname_r (fd, largebuf, (int)sizeof (largebuf));
        if (!rc)
          {
            namelen = strlen (largebuf) + 1;
            if (namelen > buflen)
              rc = ERANGE;
            else
              memcpy (buf, largebuf, namelen);
          }
      }
    else
      rc = ttyname_r (fd, buf, (int)buflen);

#  else /*!HAVE_POSIXDECL_TTYNAME_R*/
    char *name;

    if (buflen < sizeof (largebuf))
      name = ttyname_r (fd, largebuf, (int)sizeof (largebuf));
    else
      name = ttyname_r (fd, buf, (int)buflen);
    rc = name? 0 : (errno? errno : -1);
    if (!rc && buf != name)
      {
        namelen = strlen (name) + 1;
        if (namelen > buflen)
          rc = ERANGE;
        else
          memmove (buf, name, namelen);
      }
#  endif

    return rc;
  }
# else /*!HAVE_BROKEN_TTYNAME_R*/
  {
    int rc;

#  if HAVE_POSIXDECL_TTYNAME_R

    rc = ttyname_r (fd, buf, buflen);

#  else /*!HAVE_POSIXDECL_TTYNAME_R*/
    char *name;
    size_t namelen;

    name = ttyname_r (fd, buf, (int)buflen);
    rc = name? 0 : (errno? errno : -1);
    if (!rc && buf != name)
      {
        namelen = strlen (name) + 1;
        if (namelen > buflen)
          rc = ERANGE;
        else
          memmove (buf, name, namelen);
      }
#  endif

    return rc;
  }
# endif /*!HAVE_BROKEN_TTYNAME_R*/
#else /*!HAVE_TTYNAME_R*/
  char *tty;

# if HAVE_W32_SYSTEM || HAVE_ANDROID_SYSTEM
  /* We use this default one for now.  AFAICS we only need it to be
     passed to gpg and in turn to pinentry.  Providing a replacement
     is needed because elsewhere we bail out on error or Android
     provided ttyname_r prints an error message if used. */
  tty = "/dev/tty";
# else
  tty = ttyname (fd);
  if (!tty)
    return errno? errno : -1;
# endif

  strncpy (buf, tty, buflen);
  buf[buflen - 1] = '\0';
  return (strlen (tty) >= buflen) ? ERANGE : 0;
#endif /*!HAVE_TTYNAME_R*/
}

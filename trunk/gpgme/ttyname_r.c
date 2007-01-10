/* ttyname_r.c - A ttyname_r() replacement.
   Copyright (C) 2003, 2004 g10 Code GmbH

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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>


#warning ttyname is not thread-safe, and ttyname_r is missing

int
ttyname_r (int fd, char *buf, size_t buflen)
{
  char *tty;

#if HAVE_W32_SYSTEM
  /* We use this default one for now.  AFAICS we only need it to be
     passed to gpg and in turn to pinentry.  Providing a replacement
     is needed because elsewhere we bail out on error.  If we
     eventually implement a pinentry for Windows it is uinlikely that
     we need a real tty at all.  */
  tty = "/dev/tty"; 
#else
  tty = ttyname (fd);
  if (!tty)
    return errno;
#endif
  
  strncpy (buf, tty, buflen);
  buf[buflen - 1] = '\0';
  return (strlen (tty) >= buflen) ? ERANGE : 0;
}

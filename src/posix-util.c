/* posix-util.c - Utility functions for Posix
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2004 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "sys-util.h"


/* Find an executable program PGM along the envvar PATH.  */
static char *
walk_path (const char *pgm)
{
  const char *path, *s;
  char *fname, *p;

  path = getenv ("PATH");
  if (!path)
    path = "/bin:/usr/bin:.";

  fname = malloc (strlen (path) + 1 + strlen (pgm) + 1);
  if (!fname)
    return NULL;

  for (;;)
    {
      for (s=path, p=fname; *s && *s != ':'; s++, p++)
        *p = *s;
      if (*p != '/')
        *p++ = '/';
      strcpy (p, pgm);
      if (!access (fname, X_OK))
        return fname;
      if (!*s)
        break;
      path = s + 1;
    }

  free (fname);
  return NULL;
}


/* Return the full file name of the GPG binary.  This function is used
   if gpgconf was not found and thus it can be assumed that gpg2 is
   not installed.  This function is only called by get_gpgconf_item
   and may not be called concurrently.  */
char *
_gpgme_get_gpg_path (void)
{
  return walk_path ("gpg");
}


/* This function is only called by get_gpgconf_item and may not be
   called concurrently.  */
char *
_gpgme_get_gpgconf_path (void)
{
  return walk_path ("gpgconf");
}

/* See w32-util.c */
int
_gpgme_get_conf_int (const char *key, int *value)
{
  return 0;
}

void
_gpgme_allow_set_foreground_window (pid_t pid)
{
  (void)pid;
  /* Not needed.  */
}

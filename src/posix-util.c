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
#include "debug.h"

/* These variables store the malloced name of alternative default
   binaries.  The are set only once by gpgme_set_global_flag.  */
static char *default_gpg_name;
static char *default_gpgconf_name;

/* Set the default name for the gpg binary.  This function may only be
   called by gpgme_set_global_flag.  Returns 0 on success.  Leading
   directories are removed from NAME.  */
int
_gpgme_set_default_gpg_name (const char *name)
{
  const char *s;

  s = strrchr (name, '/');
  if (s)
    name = s + 1;

  if (!default_gpg_name)
    default_gpg_name = strdup (name);
  return !default_gpg_name;
}

/* Set the default name for the gpgconf binary.  This function may
   only be called by gpgme_set_global_flag.  Returns 0 on success.
   Leading directories are removed from NAME.  */
int
_gpgme_set_default_gpgconf_name (const char *name)
{
  const char *s;

  s = strrchr (name, '/');
  if (s)
    name = s + 1;

  if (!default_gpgconf_name)
    default_gpgconf_name = strdup (name);
  return !default_gpgconf_name;
}


/* Dummy function - see w32-util.c for the actual code.  */
int
_gpgme_set_override_inst_dir (const char *dir)
{
  (void)dir;
  return 0;
}


/* Find an executable program PGM along the envvar PATH.  */
static char *
walk_path (const char *pgm)
{
  const char *orig_path, *path, *s;
  char *fname, *p;

#ifdef FIXED_SEARCH_PATH
  orig_path = FIXED_SEARCH_PATH;
#else
  orig_path = getenv ("PATH");
  if (!orig_path)
    orig_path = "/bin:/usr/bin";
#endif

  fname = malloc (strlen (orig_path) + 1 + strlen (pgm) + 1);
  if (!fname)
    return NULL;

  path = orig_path;
  for (;;)
    {
      for (s=path, p=fname; *s && *s != ':'; s++, p++)
        *p = *s;
      if (p != fname && p[-1] != '/')
        *p++ = '/';
      strcpy (p, pgm);
      if (!access (fname, X_OK))
        return fname;
      if (!*s)
        break;
      path = s + 1;
    }

  _gpgme_debug (DEBUG_ENGINE, "gpgme-walk_path: '%s' not found in '%s'",
                pgm, orig_path);

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
  return walk_path (default_gpg_name? default_gpg_name : "gpg");
}


/* This function is only called by get_gpgconf_item and may not be
   called concurrently.  */
char *
_gpgme_get_gpgconf_path (void)
{
  return walk_path (default_gpgconf_name? default_gpgconf_name : "gpgconf");
}

/* See w32-util.c */
int
_gpgme_get_conf_int (const char *key, int *value)
{
  (void)key;
  (void)value;
  return 0;
}

void
_gpgme_allow_set_foreground_window (pid_t pid)
{
  (void)pid;
  /* Not needed.  */
}

/* get_env.c - A getenv() replacement.
   Copyright (C) 2003 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
 
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with GPGME; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "util.h"


#if defined(HAVE_THREAD_SAFE_GETENV) || !defined (HAVE_GETENV_R)
/* We prefer using getenv() if it is thread-safe.  */

/* Retrieve the environment variable NAME and return a copy of it in a
   malloc()'ed buffer in *VALUE.  If the environment variable is not
   set, return NULL in *VALUE.  */
gpgme_error_t
_gpgme_getenv (const char *name, char **value)
{
  char *env_value;

  env_value = getenv (name);
  if (!env_value)
    *value = NULL;
  else
    {
      *value = strdup (env_value);
      if (!*value)
	return gpg_error_from_errno (errno);
    }
  return 0;
}

#else

/* FIXME: Implement this when we have the specification for it.  */
#error Use of getenv_r not implemented.

#endif

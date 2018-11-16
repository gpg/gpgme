/* get_env.c - A getenv() replacement.
 * Copyright (C) 2003, 2004 g10 Code GmbH
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "util.h"


/* Retrieve the environment variable NAME and return a copy of it in a
   malloc()'ed buffer in *VALUE.  If the environment variable is not
   set, return NULL in *VALUE.  */

#ifdef HAVE_GETENV_R
#define INITIAL_GETENV_SIZE 32

gpgme_error_t
_gpgme_getenv (const char *name, char **value)
{
  size_t len = INITIAL_GETENV_SIZE;
  char *env_value;

  env_value = malloc (len);

  while (1)
    {
      *value = env_value;
      if (!env_value)
        return gpg_error_from_syserror ();

      if (getenv_r (name, env_value, len) == 0)
        break;

      if (errno == ERANGE)
        {
          len *= 2;
          env_value = realloc (env_value, len);
        }
      else
        {
          int saved = errno;

          free (env_value);
          *value = NULL;
          if (errno == ENOENT)
            return 0;
          else
          return gpg_error_from_errno (saved);
        }
    }

  return 0;
}
#else
#ifndef HAVE_THREAD_SAFE_GETENV
GPGRT_LOCK_DEFINE (environ_lock);
#endif

gpgme_error_t
_gpgme_getenv (const char *name, char **value)
{
  char *env_value;
  gpgme_error_t err = 0;

#ifndef HAVE_THREAD_SAFE_GETENV
  gpg_err_code_t rc;

  rc= gpgrt_lock_lock (&environ_lock);
  if (rc)
    {
      err = gpg_error (rc);
      goto leave;
    }
#endif
  env_value = getenv (name);
  if (!env_value)
    *value = NULL;
  else
    {
      *value = strdup (env_value);
      if (!*value)
	err = gpg_error_from_syserror ();
    }
#ifndef HAVE_THREAD_SAFE_GETENV
  rc = gpgrt_lock_unlock (&environ_lock);
  if (rc)
    err = gpg_error (rc);
 leave:
#endif
  return err;
}
#endif

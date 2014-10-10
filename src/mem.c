/* gpgme.c - GnuPG Made Easy.
   Copyright (C) 2014 g10 Code GmbH

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
#include <string.h>
#include "gpgme.h"
#include "util.h"
#include "mem.h"

/* The default memory management functions.  */
static struct gpgme_malloc_hooks _gpgme_default_malloc_hooks =
  { malloc, calloc, realloc, free };

void *
_gpgme_malloc (size_t size)
{
  return _gpgme_default_malloc_hooks.malloc (size);
}

void *
_gpgme_calloc (size_t nmemb, size_t size)
{
  return _gpgme_default_malloc_hooks.calloc (nmemb, size);
}

void *
_gpgme_realloc (void *p, size_t size)
{
  return _gpgme_default_malloc_hooks.realloc (p, size);
}

void
_gpgme_free (void *p)
{
  _gpgme_default_malloc_hooks.free (p);
}

char *
_gpgme_strdup (const char *s)
{
  char *r = _gpgme_malloc (strlen(s)+1);

  stpcpy (r, s);
  return r;
}

void
_gpgme_set_global_malloc_hooks (gpgme_malloc_hooks_t malloc_hooks)
{
  _gpgme_default_malloc_hooks = *malloc_hooks;
}

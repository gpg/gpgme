/* posix-util.c - Utility functions for Posix
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"

const char *
_gpgme_get_gpg_path (void)
{
#ifdef GPG_PATH
  return GPG_PATH;
#else
  return NULL;
#endif
}

const char *
_gpgme_get_gpgsm_path (void)
{
#ifdef GPGSM_PATH
  return GPGSM_PATH;
#else
  return NULL;
#endif
}

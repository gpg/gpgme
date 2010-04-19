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

const char *
_gpgme_get_gpgconf_path (void)
{
#ifdef GPGCONF_PATH
  return GPGCONF_PATH;
#else
  return NULL;
#endif
}

const char *
_gpgme_get_g13_path (void)
{
#ifdef G13_PATH
  return G13_PATH;
#else
  return NULL;
#endif
}


const char *
_gpgme_get_uiserver_socket_path (void)
{
  static char *socket_path;
  const char *homedir;
  const char name[] = "S.uiserver";

  if (socket_path)
    return socket_path;

  homedir = _gpgme_get_default_homedir ();
  if (! homedir)
    return NULL;

  socket_path = malloc (strlen (homedir) + 1 + strlen (name) + 1);
  if (! socket_path)
    return NULL;

  strcpy (stpcpy (stpcpy (socket_path, homedir), "/"), name);
  return socket_path;
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

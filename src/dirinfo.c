/* dirinfo.c - Get directory information
 * Copyright (C) 2009, 2013 g10 Code GmbH
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
#include <string.h>

#include "gpgme.h"
#include "util.h"
#include "priv-io.h"
#include "debug.h"
#include "sema.h"
#include "sys-util.h"

DEFINE_STATIC_LOCK (dirinfo_lock);

/* Constants used internally to select the data.  */
enum
  {
    WANT_HOMEDIR,
    WANT_SYSCONFDIR,
    WANT_BINDIR,
    WANT_LIBEXECDIR,
    WANT_LIBDIR,
    WANT_DATADIR,
    WANT_LOCALEDIR,
    WANT_SOCKETDIR,
    WANT_AGENT_SOCKET,
    WANT_AGENT_SSH_SOCKET,
    WANT_DIRMNGR_SOCKET,
    WANT_UISRV_SOCKET,
    WANT_GPGCONF_NAME,
    WANT_GPG_NAME,
    WANT_GPGSM_NAME,
    WANT_G13_NAME,
    WANT_KEYBOXD_NAME,
    WANT_AGENT_NAME,
    WANT_SCDAEMON_NAME,
    WANT_DIRMNGR_NAME,
    WANT_PINENTRY_NAME,
    WANT_GPG_WKS_CLIENT_NAME,
    WANT_GPGTAR_NAME,
    WANT_GPG_ONE_MODE
  };

/* Values retrieved via gpgconf and cached here.  */
static struct {
  int  valid;         /* Cached information is valid.  */
  int  disable_gpgconf;
  char *homedir;
  char *sysconfdir;
  char *bindir;
  char *libexecdir;
  char *libdir;
  char *datadir;
  char *localedir;
  char *socketdir;
  char *agent_socket;
  char *agent_ssh_socket;
  char *dirmngr_socket;
  char *uisrv_socket;
  char *gpgconf_name;
  char *gpg_name;
  char *gpgsm_name;
  char *g13_name;
  char *keyboxd_name;
  char *agent_name;
  char *scdaemon_name;
  char *dirmngr_name;
  char *pinentry_name;
  char *gpg_wks_client_name;
  char *gpgtar_name;
  int  gpg_one_mode;  /* System is in gpg1 mode.  */
} dirinfo;



/* Helper function to be used only by gpgme_set_global_flag.  */
void
_gpgme_dirinfo_disable_gpgconf (void)
{
  dirinfo.disable_gpgconf = 1;
}


/* Return the length of the directory part including the trailing
 * slash of NAME.  */
static size_t
dirname_len (const char *name)
{
  return _gpgme_get_basename (name) - name;
}


/* Parse the output of "gpgconf --list-dirs".  This function expects
   that DIRINFO_LOCK is held by the caller.  If COMPONENTS is set, the
   output of --list-components is expected. */
static void
parse_output (char *line, int components)
{
  char *value, *p;
  size_t n;

  value = strchr (line, ':');
  if (!value)
    return;
  *value++ = 0;
  if (components)
    {
      /* Skip the second field.  */
      value = strchr (value, ':');
      if (!value)
        return;
      *value++ = 0;
    }
  p = strchr (value, ':');
  if (p)
    *p = 0;
  if (_gpgme_decode_percent_string (value, &value, strlen (value)+1, 0))
    return;
  if (!*value)
    return;

  if (components)
    {
      if (!strcmp (line, "gpg") && !dirinfo.gpg_name)
        dirinfo.gpg_name = strdup (value);
      else if (!strcmp (line, "gpgsm") && !dirinfo.gpgsm_name)
        dirinfo.gpgsm_name = strdup (value);
      else if (!strcmp (line, "g13") && !dirinfo.g13_name)
        dirinfo.g13_name = strdup (value);
      else if (!strcmp (line, "keyboxd") && !dirinfo.keyboxd_name)
        dirinfo.keyboxd_name = strdup (value);
      else if (!strcmp (line, "gpg-agent") && !dirinfo.agent_name)
        dirinfo.agent_name = strdup (value);
      else if (!strcmp (line, "scdaemon") && !dirinfo.scdaemon_name)
        dirinfo.scdaemon_name = strdup (value);
      else if (!strcmp (line, "dirmngr") && !dirinfo.dirmngr_name)
        dirinfo.dirmngr_name = strdup (value);
      else if (!strcmp (line, "pinentry") && !dirinfo.pinentry_name)
        dirinfo.pinentry_name = strdup (value);
    }
  else
    {
      if (!strcmp (line, "homedir") && !dirinfo.homedir)
        dirinfo.homedir = strdup (value);
      else if (!strcmp (line, "sysconfdir") && !dirinfo.sysconfdir)
        dirinfo.sysconfdir = strdup (value);
      else if (!strcmp (line, "bindir") && !dirinfo.bindir)
        dirinfo.bindir = strdup (value);
      else if (!strcmp (line, "libexecdir") && !dirinfo.libexecdir)
        dirinfo.libexecdir = strdup (value);
      else if (!strcmp (line, "libdir") && !dirinfo.libdir)
        dirinfo.libdir = strdup (value);
      else if (!strcmp (line, "datadir") && !dirinfo.datadir)
        dirinfo.datadir = strdup (value);
      else if (!strcmp (line, "localedir") && !dirinfo.localedir)
        dirinfo.localedir = strdup (value);
      else if (!strcmp (line, "socketdir") && !dirinfo.socketdir)
        dirinfo.socketdir = strdup (value);
      else if (!strcmp (line, "agent-socket") && !dirinfo.agent_socket)
        {
          const char name[] = "S.uiserver";
          char *buffer;

          dirinfo.agent_socket = strdup (value);
          if (dirinfo.agent_socket)
            {
              n = dirname_len (dirinfo.agent_socket);
              buffer = malloc (n + strlen (name) + 1);
              if (buffer)
                {
                  strncpy (buffer, dirinfo.agent_socket, n);
                  strcpy (buffer + n, name);
                  dirinfo.uisrv_socket = buffer;
                }
            }
        }
      else if (!strcmp (line, "dirmngr-socket") && !dirinfo.dirmngr_socket)
        dirinfo.dirmngr_socket = strdup (value);
      else if (!strcmp (line, "agent-ssh-socket") && !dirinfo.agent_ssh_socket)
        dirinfo.agent_ssh_socket = strdup (value);
    }
}


/* Read the directory information from gpgconf.  This function expects
   that DIRINFO_LOCK is held by the caller.  PGNAME is the name of the
   gpgconf binary. If COMPONENTS is set, not the directories bit the
   name of the componeNts are read. */
static void
read_gpgconf_dirs (const char *pgmname, int components)
{
  char linebuf[1024] = {0};
  int linelen = 0;
  char * argv[3];
  int rp[2];
  struct spawn_fd_item_s cfd[] = { {-1, 1 /* STDOUT_FILENO */, -1, 0},
				   {-1, -1} };
  int status;
  int nread;
  char *mark = NULL;

  argv[0] = (char *)pgmname;
  argv[1] = (char*)(components? "--list-components" : "--list-dirs");
  argv[2] = NULL;

  if (_gpgme_io_pipe (rp, 1) < 0)
    return;

  cfd[0].fd = rp[1];

  status = _gpgme_io_spawn (pgmname, argv, IOSPAWN_FLAG_DETACHED,
                            cfd, NULL, NULL, NULL);
  if (status < 0)
    {
      _gpgme_io_close (rp[0]);
      _gpgme_io_close (rp[1]);
      return;
    }

  do
    {
      nread = _gpgme_io_read (rp[0],
                              linebuf + linelen,
                              sizeof linebuf - linelen - 1);
      if (nread > 0)
	{
          char *line;
          const char *lastmark = NULL;
          size_t nused;

	  linelen += nread;
	  linebuf[linelen] = '\0';

	  for (line=linebuf; (mark = strchr (line, '\n')); line = mark+1 )
	    {
              lastmark = mark;
	      if (mark > line && mark[-1] == '\r')
		mark[-1] = '\0';
              else
                mark[0] = '\0';

              parse_output (line, components);
	    }

          nused = lastmark? (lastmark + 1 - linebuf) : 0;
          memmove (linebuf, linebuf + nused, linelen - nused);
          linelen -= nused;
	}
    }
  while (nread > 0 && linelen < sizeof linebuf - 1);

  _gpgme_io_close (rp[0]);
}


static const char *
get_gpgconf_item (int what)
{
  const char *result = NULL;

  LOCK (dirinfo_lock);
  if (!dirinfo.valid)
    {
      char *pgmname;

      pgmname = dirinfo.disable_gpgconf? NULL : _gpgme_get_gpgconf_path ();
      if (pgmname && _gpgme_access (pgmname, F_OK))
        {
          _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                        "gpgme-dinfo: gpgconf='%s' [not installed]", pgmname);
          free (pgmname);
          pgmname = NULL; /* Not available.  */
        }
      else
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo: gpgconf='%s'",
                      pgmname? pgmname : "[null]");
      if (!pgmname)
        {
          /* Probably gpgconf is not installed.  Assume we are using
             GnuPG-1.  */
          dirinfo.gpg_one_mode = 1;
          pgmname = _gpgme_get_gpg_path ();
          if (pgmname)
            dirinfo.gpg_name = pgmname;
        }
      else
        {
          dirinfo.gpg_one_mode = 0;
          read_gpgconf_dirs (pgmname, 0);
          read_gpgconf_dirs (pgmname, 1);
          dirinfo.gpgconf_name = pgmname;
        }
      /* Even if the reading of the directories failed (e.g. due to an
         too old version gpgconf or no gpgconf at all), we need to
         mark the entries as valid so that we won't try over and over
         to read them.  Note further that we are not able to change
         the read values later because they are practically statically
         allocated.  */
      dirinfo.valid = 1;
      if (dirinfo.gpg_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:       gpg='%s'",
                      dirinfo.gpg_name);
      if (dirinfo.g13_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:       g13='%s'",
                      dirinfo.g13_name);
      if (dirinfo.gpgsm_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:     gpgsm='%s'",
                      dirinfo.gpgsm_name);
      if (dirinfo.keyboxd_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:   keyboxd='%s'",
                      dirinfo.keyboxd_name);
      if (dirinfo.agent_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo: gpg-agent='%s'",
                      dirinfo.agent_name);
      if (dirinfo.scdaemon_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:  scdaemon='%s'",
                      dirinfo.scdaemon_name);
      if (dirinfo.dirmngr_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:   dirmngr='%s'",
                      dirinfo.dirmngr_name);
      if (dirinfo.pinentry_name)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:  pinentry='%s'",
                      dirinfo.pinentry_name);
      if (dirinfo.homedir)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:   homedir='%s'",
                      dirinfo.homedir);
      if (dirinfo.socketdir)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:   sockdir='%s'",
                      dirinfo.socketdir);
      if (dirinfo.agent_socket)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:     agent='%s'",
                      dirinfo.agent_socket);
      if (dirinfo.agent_ssh_socket)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:       ssh='%s'",
                      dirinfo.agent_ssh_socket);
      if (dirinfo.dirmngr_socket)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:   dirmngr='%s'",
                      dirinfo.dirmngr_socket);
      if (dirinfo.uisrv_socket)
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme-dinfo:     uisrv='%s'",
                      dirinfo.uisrv_socket);
    }
  switch (what)
    {
    case WANT_HOMEDIR:    result = dirinfo.homedir; break;
    case WANT_SYSCONFDIR: result = dirinfo.sysconfdir; break;
    case WANT_BINDIR:     result = dirinfo.bindir; break;
    case WANT_LIBEXECDIR: result = dirinfo.libexecdir; break;
    case WANT_LIBDIR:     result = dirinfo.libdir; break;
    case WANT_DATADIR:    result = dirinfo.datadir; break;
    case WANT_LOCALEDIR:  result = dirinfo.localedir; break;
    case WANT_SOCKETDIR:  result = dirinfo.socketdir; break;
    case WANT_AGENT_SOCKET: result = dirinfo.agent_socket; break;
    case WANT_AGENT_SSH_SOCKET: result = dirinfo.agent_ssh_socket; break;
    case WANT_DIRMNGR_SOCKET: result = dirinfo.dirmngr_socket; break;
    case WANT_GPGCONF_NAME: result = dirinfo.gpgconf_name; break;
    case WANT_GPG_NAME:   result = dirinfo.gpg_name; break;
    case WANT_GPGSM_NAME: result = dirinfo.gpgsm_name; break;
    case WANT_G13_NAME:   result = dirinfo.g13_name; break;
    case WANT_KEYBOXD_NAME: result = dirinfo.keyboxd_name; break;
    case WANT_AGENT_NAME: result = dirinfo.agent_name; break;
    case WANT_SCDAEMON_NAME: result = dirinfo.scdaemon_name; break;
    case WANT_DIRMNGR_NAME: result = dirinfo.dirmngr_name; break;
    case WANT_PINENTRY_NAME: result = dirinfo.pinentry_name; break;
    case WANT_UISRV_SOCKET:  result = dirinfo.uisrv_socket; break;
    case WANT_GPG_ONE_MODE: result = dirinfo.gpg_one_mode? "1":NULL; break;
    case WANT_GPG_WKS_CLIENT_NAME:
      if (!dirinfo.gpg_wks_client_name && dirinfo.libexecdir)
        dirinfo.gpg_wks_client_name = _gpgme_strconcat (dirinfo.libexecdir,
                                                        "/",
                                                        "gpg-wks-client",
                                                        NULL);
      result = dirinfo.gpg_wks_client_name;
      break;
    case WANT_GPGTAR_NAME:
      if (!dirinfo.gpgtar_name && dirinfo.bindir)
        dirinfo.gpgtar_name = _gpgme_strconcat (dirinfo.bindir,
                                                "/",
                                                "gpgtar",
                                                NULL);
      result = dirinfo.gpgtar_name;
      break;
    }
  UNLOCK (dirinfo_lock);
  return result;
}


/* Return the default home directory.   Returns NULL if not known.  */
const char *
_gpgme_get_default_homedir (void)
{
  return get_gpgconf_item (WANT_HOMEDIR);
}

/* Return the default gpg-agent socket name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_agent_socket (void)
{
  return get_gpgconf_item (WANT_AGENT_SOCKET);
}

/* Return the default gpg file name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_gpg_name (void)
{
  return get_gpgconf_item (WANT_GPG_NAME);
}

/* Return the default gpgsm file name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_gpgsm_name (void)
{
  return get_gpgconf_item (WANT_GPGSM_NAME);
}

/* Return the default g13 file name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_g13_name (void)
{
  return get_gpgconf_item (WANT_G13_NAME);
}

/* Return the default gpgconf file name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_gpgconf_name (void)
{
  return get_gpgconf_item (WANT_GPGCONF_NAME);
}

/* Return the default gpgtar file name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_gpgtar_name (void)
{
  return get_gpgconf_item (WANT_GPGTAR_NAME);
}

/* Return the default UI-server socket name.  Returns NULL if not
   known.  */
const char *
_gpgme_get_default_uisrv_socket (void)
{
  return get_gpgconf_item (WANT_UISRV_SOCKET);
}

/* Return true if we are in GnuPG-1 mode - ie. no gpgconf and agent
   being optional.  */
int
_gpgme_in_gpg_one_mode (void)
{
  return !!get_gpgconf_item (WANT_GPG_ONE_MODE);
}



/* Helper function to return the basename of the passed filename.  */
const char *
_gpgme_get_basename (const char *name)
{
  const char *s;

  if (!name || !*name)
    return name;
  for (s = name + strlen (name) -1; s >= name; s--)
    if (*s == '/'
#ifdef HAVE_W32_SYSTEM
        || *s == '\\' || *s == ':'
#endif
        )
      return s+1;
  return name;
}


/* Return default values for various directories and file names.  */
const char *
gpgme_get_dirinfo (const char *what)
{
  if (!what)
    return NULL;
  else if (!strcmp (what, "homedir"))
    return get_gpgconf_item (WANT_HOMEDIR);
  else if (!strcmp (what, "agent-socket"))
    return get_gpgconf_item (WANT_AGENT_SOCKET);
  else if (!strcmp (what, "uiserver-socket"))
    return get_gpgconf_item (WANT_UISRV_SOCKET);
  else if (!strcmp (what, "gpgconf-name"))
    return get_gpgconf_item (WANT_GPGCONF_NAME);
  else if (!strcmp (what, "gpg-name"))
    return get_gpgconf_item (WANT_GPG_NAME);
  else if (!strcmp (what, "gpgsm-name"))
    return get_gpgconf_item (WANT_GPGSM_NAME);
  else if (!strcmp (what, "g13-name"))
    return get_gpgconf_item (WANT_G13_NAME);
  else if (!strcmp (what, "keyboxd-name"))
    return get_gpgconf_item (WANT_KEYBOXD_NAME);
  else if (!strcmp (what, "agent-name"))
    return get_gpgconf_item (WANT_AGENT_NAME);
  else if (!strcmp (what, "scdaemon-name"))
    return get_gpgconf_item (WANT_SCDAEMON_NAME);
  else if (!strcmp (what, "dirmngr-name"))
    return get_gpgconf_item (WANT_DIRMNGR_NAME);
  else if (!strcmp (what, "pinentry-name"))
    return get_gpgconf_item (WANT_PINENTRY_NAME);
  else if (!strcmp (what, "gpg-wks-client-name"))
    return get_gpgconf_item (WANT_GPG_WKS_CLIENT_NAME);
  else if (!strcmp (what, "gpgtar-name"))
    return get_gpgconf_item (WANT_GPGTAR_NAME);
  else if (!strcmp (what, "agent-ssh-socket"))
    return get_gpgconf_item (WANT_AGENT_SSH_SOCKET);
  else if (!strcmp (what, "dirmngr-socket"))
    return get_gpgconf_item (WANT_DIRMNGR_SOCKET);
  else if (!strcmp (what, "sysconfdir"))
    return get_gpgconf_item (WANT_SYSCONFDIR);
  else if (!strcmp (what, "bindir"))
    return get_gpgconf_item (WANT_BINDIR);
  else if (!strcmp (what, "libexecdir"))
    return get_gpgconf_item (WANT_LIBEXECDIR);
  else if (!strcmp (what, "libdir"))
    return get_gpgconf_item (WANT_LIBDIR);
  else if (!strcmp (what, "datadir"))
    return get_gpgconf_item (WANT_DATADIR);
  else if (!strcmp (what, "localedir"))
    return get_gpgconf_item (WANT_LOCALEDIR);
  else if (!strcmp (what, "socketdir"))
    return get_gpgconf_item (WANT_SOCKETDIR);
  else
    return NULL;
}

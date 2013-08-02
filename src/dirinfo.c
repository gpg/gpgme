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
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
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
    WANT_AGENT_SOCKET,
    WANT_GPG_NAME,
    WANT_GPGSM_NAME,
    WANT_G13_NAME,
    WANT_UISRV_SOCKET
  };

/* Values retrieved via gpgconf and cached here.  */
static struct {
  int  valid;         /* Cached information is valid.  */
  char *homedir;
  char *agent_socket;
  char *gpg_name;
  char *gpgsm_name;
  char *g13_name;
  char *uisrv_socket;
} dirinfo;


/* Parse the output of "gpgconf --list-dirs".  This function expects
   that DIRINFO_LOCK is held by the caller.  If COMPONENTS is set, the
   output of --list-components is expected. */
static void
parse_output (char *line, int components)
{
  char *value, *p;

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
    }
  else
    {
      if (!strcmp (line, "homedir") && !dirinfo.homedir)
        {
          const char name[] = "S.uiserver";

          dirinfo.homedir = strdup (value);
          if (dirinfo.homedir)
            {
              dirinfo.uisrv_socket = malloc (strlen (dirinfo
                                                     .homedir)
                                             + 1 + strlen (name) + 1);
              if (dirinfo.uisrv_socket)
                strcpy (stpcpy (stpcpy (dirinfo.uisrv_socket, dirinfo.homedir),
                                DIRSEP_S), name);
            }
        }
      else if (!strcmp (line, "agent-socket") && !dirinfo.agent_socket)
        dirinfo.agent_socket = strdup (value);
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
  argv[1] = components? "--list-components" : "--list-dirs";
  argv[2] = NULL;

  if (_gpgme_io_pipe (rp, 1) < 0)
    return;

  cfd[0].fd = rp[1];

  status = _gpgme_io_spawn (pgmname, argv, 0, cfd, NULL, NULL, NULL);
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
      const char *pgmname;

      pgmname = _gpgme_get_gpgconf_path ();
      if (pgmname && access (pgmname, F_OK))
        {
          _gpgme_debug (DEBUG_INIT,
                        "gpgme_dinfo: gpgconf='%s' [not installed]\n", pgmname);
          pgmname = NULL; /* Not available.  */
        }
      else
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo: gpgconf='%s'\n",
                      pgmname? pgmname : "[null]");
      if (!pgmname)
        {
          /* Probably gpgconf is not installed.  Assume we are using
             GnuPG-1.  */
          pgmname = _gpgme_get_gpg_path ();
          if (pgmname)
            dirinfo.gpg_name = strdup (pgmname);
        }
      else
        {
          read_gpgconf_dirs (pgmname, 0);
          read_gpgconf_dirs (pgmname, 1);
        }
      /* Even if the reading of the directories failed (e.g. due to an
         too old version gpgconf or no gpgconf at all), we need to
         mark the entries as valid so that we won't try over and over
         to read them.  Note further that we are not able to change
         the read values later because they are practically statically
         allocated.  */
      dirinfo.valid = 1;
      if (dirinfo.gpg_name)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo:     gpg='%s'\n",
                      dirinfo.gpg_name);
      if (dirinfo.g13_name)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo:     g13='%s'\n",
                      dirinfo.g13_name);
      if (dirinfo.gpgsm_name)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo:   gpgsm='%s'\n",
                      dirinfo.gpgsm_name);
      if (dirinfo.homedir)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo: homedir='%s'\n",
                      dirinfo.homedir);
      if (dirinfo.agent_socket)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo:   agent='%s'\n",
                      dirinfo.agent_socket);
      if (dirinfo.uisrv_socket)
        _gpgme_debug (DEBUG_INIT, "gpgme_dinfo:   uisrv='%s'\n",
                      dirinfo.uisrv_socket);
    }
  switch (what)
    {
    case WANT_HOMEDIR: result = dirinfo.homedir; break;
    case WANT_AGENT_SOCKET: result = dirinfo.agent_socket; break;
    case WANT_GPG_NAME:   result = dirinfo.gpg_name; break;
    case WANT_GPGSM_NAME: result = dirinfo.gpgsm_name; break;
    case WANT_G13_NAME:   result = dirinfo.g13_name; break;
    case WANT_UISRV_SOCKET:  result = dirinfo.uisrv_socket; break;
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

/* Return the default gpgconf file name.  Returns NULL if not known.
   Because gpgconf is the binary used to retrieved all these default
   names, this function is merely a simple wrapper around the function
   used to locate this binary.  */
const char *
_gpgme_get_default_gpgconf_name (void)
{
  return _gpgme_get_gpgconf_path ();
}

/* Return the default UI-server socket name.  Returns NULL if not
   known.  */
const char *
_gpgme_get_default_uisrv_socket (void)
{
  return get_gpgconf_item (WANT_UISRV_SOCKET);
}

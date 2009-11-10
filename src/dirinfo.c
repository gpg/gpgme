/* dirinfo.c - Get directory information
 * Copyright (C) 2009 g10 Code GmbH
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

DEFINE_STATIC_LOCK (dirinfo_lock);

/* Constants used internally to select the data.  */
enum 
  {
    WANT_HOMEDIR,
    WANT_AGENT_SOCKET
  };

/* Values retrieved via gpgconf and cached here.  */
static struct {
  int  valid;         /* Cached information is valid.  */
  char *homedir;
  char *agent_socket;
} dirinfo;


/* Parse the output of "gpgconf --list-dirs".  This function expects
   that DIRINFO_LOCK is held by the caller.  */
static void
parse_output (char *line)
{
  char *value, *p;

  value = strchr (line, ':');
  if (!value)
    return;
  *value++ = 0;
  p = strchr (value, ':');
  if (p)
    *p = 0;
  if (_gpgme_decode_percent_string (value, &value, strlen (value)+1, 0))
    return;
  if (!*value)
    return;
  
  if (!strcmp (line, "homedir") && !dirinfo.homedir)
    dirinfo.homedir = strdup (value);
  else if (!strcmp (line, "agent-socket") && !dirinfo.agent_socket)
    dirinfo.agent_socket = strdup (value);
}


/* Read the directory information from gpgconf.  This function expects
   that DIRINFO_LOCK is held by the caller.  */
static void
read_gpgconf_dirs (void) 
{
  const char *pgmname;
  char linebuf[1024] = {0};
  int linelen = 0;
  char * argv[3];
  int rp[2];
  struct spawn_fd_item_s cfd[] = { {-1, 1 /* STDOUT_FILENO */, -1, 0},
				   {-1, -1} };
  int status;
  int nread;
  char *mark = NULL;

  pgmname = _gpgme_get_gpgconf_path ();
  if (!pgmname)
    return;  /* No way.  */

  argv[0] = (char *)pgmname;
  argv[1] = "--list-dirs";
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

              parse_output (line);
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
get_gpgconf_dir (int what)
{
  const char *result = NULL;

  LOCK (dirinfo_lock);
  if (!dirinfo.valid)
    {
      read_gpgconf_dirs ();
      /* Even if the reading of the directories failed (e.g. due to an
         too old version gpgconf or no gpgconf at all), we need to
         mark the entries as valid so that we won't try over and over
         to read them.  Note further that we are not able to change
         the read values later because they are practically statically
         allocated.  */
      dirinfo.valid = 1;
    }
  switch (what)
    {
    case WANT_HOMEDIR: result = dirinfo.homedir; break;
    case WANT_AGENT_SOCKET: result = dirinfo.agent_socket; break;
    }
  UNLOCK (dirinfo_lock);
  return result;
}


/* Return the default home directory.   Returns NULL if not known.  */
const char *
_gpgme_get_default_homedir (void)
{
  return get_gpgconf_dir (WANT_HOMEDIR);
}

/* Return the default gpg-agent socket name.  Returns NULL if not known.  */
const char *
_gpgme_get_default_agent_socket (void)
{
  return get_gpgconf_dir (WANT_AGENT_SOCKET);
}


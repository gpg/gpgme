/* version.c -  version check
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "gpgme.h"
#include "context.h"
#include "sema.h"
#include "util.h"
#include "key.h" /* for key_cache_init */
#include "io.h"


static void
do_subsystem_inits (void)
{
  static int done = 0;

  if (done)
    return;
  _gpgme_sema_subsystem_init ();
  _gpgme_key_cache_init ();
  done = 1;
}

static const char*
parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && isdigit(s[1]))
    return NULL;  /* Leading zeros are not allowed.  */
  for (; isdigit(*s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0 ? NULL : s;
}

static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, micro);
  if (!s)
    return NULL;
  return s;  /* Patchlevel.  */
}

const char *
_gpgme_compare_versions (const char *my_version,
			 const char *req_version)
{
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!req_version)
    return my_version;
  if (!my_version)
    return NULL;

  my_plvl = parse_version_string (my_version, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;	/* Very strange: our own version is bogus.  */
  rq_plvl = parse_version_string(req_version,
				 &rq_major, &rq_minor, &rq_micro);
  if (!rq_plvl)
    return NULL;	/* Requested version string is invalid.  */

  if (my_major > rq_major
	|| (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor 
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro
	  && strcmp( my_plvl, rq_plvl ) >= 0))
    {
      return my_version;
    }
  return NULL;
}

/**
 * gpgme_check_version:
 * @req_version: A string with a version
 * 
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * met.  If a NULL is passed to this function, no check is done and
 * the version string is simply returned.  It is a pretty good idea to
 * run this function as soon as possible, because it also intializes 
 * some subsystems.  In a multithreaded environment if should be called
 * before the first thread is created.
 * 
 * Return value: The version string or NULL
 **/
const char *
gpgme_check_version (const char *req_version)
{
  do_subsystem_inits ();
  return _gpgme_compare_versions (VERSION, req_version);
}


/* Get the information about the configured and installed engines.  A
   pointer to the first engine in the statically allocated linked list
   is returned in *INFO.  If an error occurs, it is returned.  */
GpgmeError
gpgme_get_engine_info (GpgmeEngineInfo *info)
{
  static GpgmeEngineInfo engine_info;
  DEFINE_STATIC_LOCK (engine_info_lock);

  LOCK (engine_info_lock);
  if (!engine_info)
    {
      GpgmeEngineInfo *lastp = &engine_info;
      GpgmeProtocol proto_list[] = { GPGME_PROTOCOL_OpenPGP,
				     GPGME_PROTOCOL_CMS };
      int proto;

      for (proto = 0; proto < DIM (proto_list); proto++)
	{
	  const char *path = _gpgme_engine_get_path (proto_list[proto]);

	  if (!path)
	    continue;

	  *lastp = malloc (sizeof (*engine_info));
	  if (!*lastp)
	    {
	      while (engine_info)
		{
		  GpgmeEngineInfo next_info = engine_info->next;
		  free (engine_info);
		  engine_info = next_info;
		}
	      UNLOCK (engine_info_lock);
	      return GPGME_Out_Of_Core;
	    }

	  (*lastp)->protocol = proto_list[proto];
	  (*lastp)->path = path;
	  (*lastp)->version = _gpgme_engine_get_version (proto_list[proto]);
	  (*lastp)->req_version
	    = _gpgme_engine_get_req_version (proto_list[proto]);
	  lastp = &(*lastp)->next;
	}
    }
  UNLOCK (engine_info_lock);
  *info = engine_info;
  return 0;
}


#define LINELENGTH 80

char *
_gpgme_get_program_version (const char *const path)
{
  char line[LINELENGTH] = "";
  int linelen = 0;
  char *mark = NULL;
  int rp[2];
  int nread;
  char *argv[] = {NULL /* path */, "--version", 0};
  struct spawn_fd_item_s pfd[] = { {0, -1}, {-1, -1} };
  struct spawn_fd_item_s cfd[] = { {-1, 1 /* STDOUT_FILENO */}, {-1, -1} };
  int status;

  if (!path)
    return NULL;
  argv[0] = (char *) path;

  if (_gpgme_io_pipe (rp, 1) < 0)
    return NULL;

  pfd[0].fd = rp[1];
  cfd[0].fd = rp[1];

  status = _gpgme_io_spawn (path, argv, cfd, pfd);
  if (status < 0)
    {
      _gpgme_io_close (rp[0]);
      _gpgme_io_close (rp[1]);
      return NULL;
    }

  do
    {
      nread = _gpgme_io_read (rp[0], &line[linelen], LINELENGTH - linelen - 1);
      if (nread > 0)
	{
	  line[linelen + nread] = '\0';
	  mark = strchr (&line[linelen], '\n');
	  if (mark)
	    {
	      *mark = '\0';
	      break;
	    }
	  linelen += nread;
	}
    }
  while (nread > 0 && linelen < LINELENGTH - 1);

  _gpgme_io_close (rp[0]);

  if (mark)
    {
      mark = strrchr (line, ' ');
      if (!mark)
	return NULL;
      return strdup (mark + 1);
    }

  return NULL;
}

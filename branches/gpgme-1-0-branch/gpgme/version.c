/* version.c - Version check routines.
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
#include <string.h>
#include <limits.h>
#include <ctype.h>

#include "gpgme.h"
#include "io.h"

/* For _gpgme_sema_subsystem_init ().  */
#include "sema.h"


/* Bootstrap the subsystems needed for concurrent operation.  This
   must be done once at startup.  We can not guarantee this using a
   lock, though, because the semaphore subsystem needs to be
   initialized itself before it can be used.  So we expect that the
   user performs the necessary syncrhonization.  */
static void
do_subsystem_inits (void)
{
  static int done = 0;

  if (done)
    return;

  _gpgme_sema_subsystem_init ();
  _gpgme_io_subsystem_init ();

  done = 1;
}


/* Read the next number in the version string STR and return it in
   *NUMBER.  Return a pointer to the tail of STR after parsing, or
   *NULL if the version string was invalid.  */
static const char *
parse_version_number (const char *str, int *number)
{
#define MAXVAL ((INT_MAX - 10) / 10)
  int val = 0;

  /* Leading zeros are not allowed.  */
  if (*str == '0' && isdigit(str[1]))
    return NULL;

  while (isdigit (*str) && val <= MAXVAL)
    {
      val *= 10;
      val += *(str++) - '0';
    }
  *number = val;
  return val > MAXVAL ? NULL : str;
}


/* Parse the version string STR in the format MAJOR.MINOR.MICRO (for
   example, 9.3.2) and return the components in MAJOR, MINOR and MICRO
   as integers.  The function returns the tail of the string that
   follows the version number.  This might be te empty string if there
   is nothing following the version number, or a patchlevel.  The
   function returns NULL if the version string is not valid.  */
static const char *
parse_version_string (const char *str, int *major, int *minor, int *micro)
{
  str = parse_version_number (str, major);
  if (!str || *str != '.')
    return NULL;
  str++;

  str = parse_version_number (str, minor);
  if (!str || *str != '.')
    return NULL;
  str++;

  str = parse_version_number (str, micro);
  if (!str)
    return NULL;

  /* A patchlevel might follow.  */
  return str;
}


const char *
_gpgme_compare_versions (const char *my_version,
			 const char *rq_version)
{
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!rq_version)
    return my_version;
  if (!my_version)
    return NULL;

  my_plvl = parse_version_string (my_version, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;

  rq_plvl = parse_version_string (rq_version, &rq_major, &rq_minor, &rq_micro);
  if (!rq_plvl)
    return NULL;

  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor 
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro && strcmp (my_plvl, rq_plvl) >= 0))
    return my_version;

  return NULL;
}


/* Check that the the version of the library is at minimum the
   requested one and return the version string; return NULL if the
   condition is not met.  If a NULL is passed to this function, no
   check is done and the version string is simply returned.

   This function must be run once at startup, as it also initializes
   some subsystems.  Its invocation must be synchronized against
   calling any of the other functions in a multi-threaded
   environments.  */
const char *
gpgme_check_version (const char *req_version)
{
  do_subsystem_inits ();
  return _gpgme_compare_versions (VERSION, req_version);
}


#define LINELENGTH 80

/* Retrieve the version number from the --version output of the
   program FILE_NAME.  */
char *
_gpgme_get_program_version (const char *const file_name)
{
  char line[LINELENGTH] = "";
  int linelen = 0;
  char *mark = NULL;
  int rp[2];
  int nread;
  char *argv[] = {NULL /* file_name */, "--version", 0};
  struct spawn_fd_item_s pfd[] = { {0, -1}, {-1, -1} };
  struct spawn_fd_item_s cfd[] = { {-1, 1 /* STDOUT_FILENO */}, {-1, -1} };
  int status;

  if (!file_name)
    return NULL;
  argv[0] = (char *) file_name;

  if (_gpgme_io_pipe (rp, 1) < 0)
    return NULL;

  pfd[0].fd = rp[1];
  cfd[0].fd = rp[1];

  status = _gpgme_io_spawn (file_name, argv, cfd, pfd);
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

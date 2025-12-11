/* version.c - Version check routines.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2008 g10 Code GmbH
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
#include <limits.h>
#include <ctype.h>
#ifdef HAVE_W32_SYSTEM
#include <winsock2.h>
#endif

#include "gpgme.h"
#include "util.h"
#include "priv-io.h"
#include "debug.h"
#include "context.h"

/* For _gpgme_sema_subsystem_init and _gpgme_status_init.  */
#include "sema.h"
#include "util.h"

#ifdef HAVE_ASSUAN_H
#include "assuan.h"
#endif

#ifdef HAVE_W32_SYSTEM
#include "windows.h"
#endif

/* We implement this function, so we have to disable the overriding
   macro.  */
#undef gpgme_check_version


/* Bootstrap the subsystems needed for concurrent operation.  This
   must be done once at startup.  We can not guarantee this using a
   lock, though, because the semaphore subsystem needs to be
   initialized itself before it can be used.  So we expect that the
   user performs the necessary synchronization.  */
static void
do_subsystem_inits (void)
{
  static int done = 0;

  if (done)
    return;

#ifdef HAVE_W32_SYSTEM
  /* We need to make sure that the sockets are initialized.  */
  {
    WSADATA wsadat;

    WSAStartup (0x202, &wsadat);
  }

  /* We want gpgrt's gettext to always output UTF-8. */
#if GPGRT_VERSION_NUMBER >= 0x013300 /* >= 1.51 */
  gettext_use_utf8 (3);
#else
  gettext_use_utf8 (1);
#endif
#endif

  _gpgme_debug_subsystem_init ();
  _gpgme_io_subsystem_init ();
  _gpgme_status_init ();

  done = 1;
}


/* Put vesion information into the binary.  */
static const char *
cright_blurb (void)
{
  static const char blurb[] =
    "\n\n"
    "This is GPGME " PACKAGE_VERSION " - The GnuPG Made Easy library\n"
    CRIGHTBLURB
    "\n"
    "("  BUILD_COMMITID " " BUILD_TIMESTAMP ")\n"
    "\n\n";
  return blurb;
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
   follows the version number.  This might be the empty string if there
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


/* Return true if MY_VERSION is at least REQ_VERSION, and false
   otherwise.  */
int
_gpgme_compare_versions (const char *my_version,
			 const char *rq_version)
{
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!rq_version)
    return 1;
  if (!my_version)
    return 0;

  my_plvl = parse_version_string (my_version, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return 0;

  rq_plvl = parse_version_string (rq_version, &rq_major, &rq_minor, &rq_micro);
  if (!rq_plvl)
    return 0;

  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro && strcmp (my_plvl, rq_plvl) >= 0))
    return 1;

  return 0;
}


/* Check that the version of the library is at minimum the
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
  const char *result;
  do_subsystem_inits ();

  /* Catch-22: We need to get at least the debug subsystem ready
     before using the trace facility.  If we won't the trace would
     automagically initialize the debug system without the locks
     being initialized and missing the assuan log level setting. */
  TRACE (DEBUG_INIT, "gpgme_check_version", NULL,
	  "req_version=%s, VERSION=%s",
          req_version? req_version:"(null)", VERSION);

  result = _gpgme_compare_versions (VERSION, req_version) ? VERSION : NULL;
  if (result != NULL)
    _gpgme_selftest = 0;

  return result;
}

/* Check the version and also at runtime if the struct layout of the
   library matches the one of the user.  This is particular useful for
   Windows targets (-mms-bitfields).  */
const char *
gpgme_check_version_internal (const char *req_version,
			      size_t offset_sig_validity)
{
  const char *result;

  if (req_version && req_version[0] == 1 && req_version[1] == 1)
    return cright_blurb ();
  result = gpgme_check_version (req_version);
  if (result == NULL)
    return result;

  /* Catch-22, see above.  */
  TRACE (DEBUG_INIT, "gpgme_check_version_internal", NULL,
	  "req_version=%s, offset_sig_validity=%zu",
	  req_version ? req_version : "(null)", offset_sig_validity);

  if (offset_sig_validity != offsetof (struct _gpgme_signature, validity))
    {
      TRACE (DEBUG_INIT, "gpgme_check_version_internal", NULL,
	      "offset_sig_validity mismatch: expected %i",
             (int)offsetof (struct _gpgme_signature, validity));
      _gpgme_selftest = GPG_ERR_SELFTEST_FAILED;
    }

  return result;
}


#define LINELENGTH 80

/* Extract the version string of a program from STRING.  The version
   number is expected to be in GNU style format:

     foo 1.2.3
     foo (bar system) 1.2.3
     foo 1.2.3 cruft
     foo (bar system) 1.2.3 cruft.

  Spaces and tabs are skipped and used as delimiters, a term in
  (nested) parenthesis before the version string is skipped, the
  version string may consist of any non-space and non-tab characters
  but needs to bstart with a digit.
*/
static const char *
extract_version_string (const char *string, size_t *r_len)
{
  const char *s;
  int count, len;

  for (s=string; *s; s++)
    if (*s == ' ' || *s == '\t')
        break;
  while (*s == ' ' || *s == '\t')
    s++;
  if (*s == '(')
    {
      for (count=1, s++; count && *s; s++)
        if (*s == '(')
          count++;
        else if (*s == ')')
          count--;
    }
  /* For robustness we look for a digit.  */
  while ( *s && !(*s >= '0' && *s <= '9') )
    s++;
  if (*s >= '0' && *s <= '9')
    {
      for (len=0; s[len]; len++)
        if (s[len] == ' ' || s[len] == '\t')
          break;
    }
  else
    len = 0;

  *r_len = len;
  return s;
}


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
  char *argv[] = {NULL /* file_name */, (char*)"--version", 0};
  struct spawn_fd_item_s cfd[] = { {-1, 1 /* STDOUT_FILENO */, -1, 0},
				   {-1, -1} };
  int status;

  if (!file_name)
    return NULL;
  argv[0] = (char *) file_name;

  if (_gpgme_io_pipe (rp, 1) < 0)
    return NULL;

  cfd[0].fd = rp[1];

  status = _gpgme_io_spawn (file_name, argv,
                            IOSPAWN_FLAG_DETACHED, cfd, NULL, NULL, NULL);
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
	      if (mark > &line[0] && mark[-1] == '\r')
		mark--;
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
      size_t len;
      const char *s;

      s = extract_version_string (line, &len);
      if (!len)
        return NULL;
      mark = malloc (len + 1);
      if (!mark)
	return NULL;
      memcpy (mark, s, len);
      mark[len] = 0;
      return mark;
    }

  return NULL;
}

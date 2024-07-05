/* debug.c - helpful output in desperate situations
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001-2005, 2007, 2009, 2019-2023 g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <time.h>
#ifndef HAVE_DOSISH_SYSTEM
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
# endif
# include <fcntl.h>
#endif
#include <assert.h>

#ifdef HAVE_W32_SYSTEM
#include <winsock2.h>
#include <windows.h>
#endif

#include "util.h"
#include "sema.h"
#include "sys-util.h"
#include "debug.h"


/* The amount of detail requested by the user, per environment
   variable GPGME_DEBUG.  */
static int debug_level;

/* If not NULL, this malloced string is used instead of the
   GPGME_DEBUG envvar.  It must have been set before the debug
   subsystem has been initialized.  Using it later may or may not have
   any effect.  */
static char *envvar_override;


#ifdef HAVE_TLS
#define FRAME_NR
static __thread int frame_nr = 0;
#endif

void
_gpgme_debug_frame_begin (void)
{
#ifdef FRAME_NR
  frame_nr++;
#endif
}

int _gpgme_debug_frame_end (void)
{
#ifdef FRAME_NR
  frame_nr--;
#endif
  return 0;
}



/* Remove leading and trailing white spaces.  */
static char *
trim_spaces (char *str)
{
  char *string, *p, *mark;

  string = str;
  /* Find first non space character.  */
  for (p = string; *p && isspace (*(unsigned char *) p); p++)
    ;
  /* Move characters.  */
  for (mark = NULL; (*string = *p); string++, p++)
    if (isspace (*(unsigned char *) p))
      {
	if (!mark)
	  mark = string;
      }
    else
      mark = NULL;
  if (mark)
    *mark = '\0';	/* Remove trailing spaces.  */

  return str;
}


/* This is an internal function to set debug info.  The caller must
   assure that this function is called only by one thread at a time.
   The function may have no effect if called after the debug system
   has been initialized.  Returns 0 on success.  */
int
_gpgme_debug_set_debug_envvar (const char *value)
{
  free (envvar_override);
  envvar_override = strdup (value);
  return !envvar_override;
}


static int
safe_to_use_debug_file (void)
{
#ifdef HAVE_DOSISH_SYSTEM
  return 1;
#else /* Unix */
  return (getuid () == geteuid ()
#if defined(HAVE_GETGID) && defined(HAVE_GETEGID)
          && getgid () == getegid ()
#endif
          );
#endif /* Unix */
}


#if defined(HAVE_W32_SYSTEM) || defined(__linux)
static int
tid_log_callback (unsigned long *rvalue)
{
  int len = sizeof (*rvalue);
  uintptr_t thread;

#ifdef HAVE_W32_SYSTEM
  thread = (uintptr_t)GetCurrentThreadId ();
#elif defined(__linux)
  thread = (uintptr_t)gettid ();
#endif
  if (sizeof (thread) < len)
    {
      int zerolen = len;

      len = sizeof (thread);
      zerolen -= len;
      memset (rvalue + len, 0, zerolen);
    }
  memcpy (rvalue, &thread, len);

  return 2; /* Use use hex representation.  */
}
#endif


static void
debug_init (void)
{
  static int initialized;

  if (!initialized)
    {
      gpgme_error_t err;
      char *e;
      const char *s1, *s2;

      if (envvar_override)
        {
          e = strdup (envvar_override);
          free (envvar_override);
          envvar_override = NULL;
        }
      else
        {
          err = _gpgme_getenv ("GPGME_DEBUG", &e);
          if (err)
            return;
        }

      initialized = 1;
      if (e)
	{
          char *p, *r;
          unsigned int flags;

	  debug_level = atoi (e);
          s1 = strchr (e, PATHSEP_C);
          if (s1 && safe_to_use_debug_file ())
            {
              s1++;
              if (!(s2 = strchr (s1, PATHSEP_C)))
                s2 = s1 + strlen (s1);
              p = malloc (s2 - s1 + 1);
              if (p)
                {
                  memcpy (p, s1, s2 - s1);
                  p[s2-s1] = 0;
                  trim_spaces (p);
                  if (strstr (p, "^//"))
                    {
                      /* map chars to allow socket: and tcp: */
                      for (r=p; *r; r++)
                        if (*r == '^')
                          *r = ':';
                    }
                  if (*p)
                    gpgrt_log_set_sink (p, NULL, -1);
                  free (p);
                }
            }
	  free (e);

          gpgrt_log_get_prefix (&flags);
          flags |= (GPGRT_LOG_WITH_PREFIX
                    | GPGRT_LOG_WITH_TIME
                    | GPGRT_LOG_WITH_PID);
          gpgrt_log_set_prefix (*gpgrt_log_get_prefix (NULL)?NULL:"gpgme",
                                flags);
#if defined(HAVE_W32_SYSTEM) || defined(__linux)
          gpgrt_log_set_pid_suffix_cb (tid_log_callback);
#endif
        }
    }

  if (debug_level > 0)
    {
      _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                    "gpgme_debug: level=%d", debug_level);
#ifdef HAVE_W32_SYSTEM
      {
        const char *name = _gpgme_get_inst_dir ();
        _gpgme_debug (NULL, DEBUG_INIT, -1, NULL, NULL, NULL,
                      "gpgme_debug: gpgme='%s'", name? name: "?");
      }
#endif
    }
}



/* This should be called as soon as possible.  It is required so that
 * the assuan logging gets connected to the gpgme log stream as early
 * as possible.  */
void
_gpgme_debug_subsystem_init (void)
{
  debug_init ();
}




/* Log the formatted string FORMAT prefixed with additional info
 * depending on MODE:
 *
 * -1 = Do not print any additional args.
 *  0 = standalone (used by macro TRACE)
 *  1 = enter a function (used by macro TRACE_BEG)
 *  2 = debug a function (used by macro TRACE_LOG)
 *  3 = leave a function (used by macro TRACE_SUC)
 *
 * If LINE is not NULL the output will be stored in that variabale but
 * without a LF.  _gpgme_debug_add can be used to add more and
 * _gpgme_debug_end to finally output it.
 *
 * Returns: 0
 *
 * Note that we always return 0 because the old TRACE macro evaluated
 * to 0 which issues a warning with newer gcc version about an unused
 * values.  By using a return value of this function this can be
 * avoided.  Fixme: It might be useful to check whether the return
 * value from the TRACE macros are actually used somewhere.
 */
int
_gpgme_debug (void **line, int level, int mode,
              const char *func, const char *tagname,
              const char *tagvalue, const char *format, ...)
{
  va_list arg_ptr;
  int saved_errno;
  int indent;
  char *stdinfo, *userinfo;
  const char *modestr;
  int no_userinfo = 0;

  if (debug_level < level)
    return 0;

#ifdef FRAME_NR
    indent = frame_nr > 0? (2 * (frame_nr - 1)):0;
#else
    indent = 0;
#endif

  saved_errno = errno;
  va_start (arg_ptr, format);

  switch (mode)
    {
    case -1: modestr = NULL; break; /* Do nothing.  */
    case 0: modestr = "call"; break;
    case 1: modestr = "enter"; break;
    case 2: modestr = "check"; break;
    case 3: modestr = "leave"; break;
    default: modestr = "mode?"; break;
    }

  if (!modestr)
    stdinfo = NULL;
  else if (tagname && strcmp (tagname, XSTRINGIFY (NULL)))
    stdinfo = gpgrt_bsprintf ("%s: %s: %s=%p ", func,modestr,tagname,tagvalue);
  else
    stdinfo = gpgrt_bsprintf ("%s: %s: ", func, modestr);

  if (format && *format)
    userinfo = gpgrt_vbsprintf (format, arg_ptr);
  else
    {
      userinfo = NULL;
      no_userinfo = 1;
    }
  va_end (arg_ptr);

  if (line)
    *line = gpgrt_bsprintf ("%s%s",
                            (!modestr ? "" :
                             stdinfo  ? stdinfo :
                             (!format || !*format)? "" :"out-of-core "),
                            userinfo? userinfo : "out-of-core");
  else
    {
      gpgrt_log (GPGRT_LOGLVL_INFO, "%*s%s%s",
                 indent < 40? indent : 40, "",
                 (!modestr ? "" :
                  stdinfo  ? stdinfo :
                  (!format || !*format)? "" : "out-of-core "),
                 (userinfo? userinfo :
                  no_userinfo? "" : "out-of-core"));
    }

  gpgrt_free (userinfo);
  gpgrt_free (stdinfo);
  gpg_err_set_errno (saved_errno);
  return 0;
}


/* Add the formatted string FORMAT to the debug line *LINE.  */
void
_gpgme_debug_add (void **line, const char *format, ...)
{
  va_list arg_ptr;
  char *toadd;
  char *result;
  int res;

  if (!*line)
    return;

  va_start (arg_ptr, format);
  res = gpgrt_vasprintf (&toadd, format, arg_ptr);
  va_end (arg_ptr);
  if (res < 0)
    {
      gpgrt_free (*line);
      *line = NULL;
    }
  res = gpgrt_asprintf (&result, "%s%s", *(char **) line, toadd);
  gpgrt_free (toadd);
  gpgrt_free (*line);
  if (res < 0)
    *line = NULL;
  else
    *line = result;
}


/* Finish construction of *LINE and send it to the debug output
   stream.  */
void
_gpgme_debug_end (void **line)
{
  const char *string;

  if (!*line)
    return;
  string = *line;

  gpgrt_log (GPGRT_LOGLVL_INFO, "%s", string);
  gpgrt_free (*line);
  *line = NULL;
}


#define TOHEX(val) (((val) < 10) ? ((val) + '0') : ((val) - 10 + 'a'))

void
_gpgme_debug_buffer (int lvl, const char *const fmt,
		     const char *const func, const char *const buffer,
		     size_t len)
{
  int idx = 0;
  int j;

  if (!_gpgme_debug_trace ())
    return;

  if (!buffer)
    return;

  if (lvl > 9)
    {
      while (idx < len)
        {
          char str[51];
          char *strp = str;
          char *strp2 = &str[34];

          for (j = 0; j < 16; j++)
            {
              unsigned char val;
              if (idx < len)
                {
                  val = buffer[idx++];
                  *(strp++) = TOHEX (val >> 4);
                  *(strp++) = TOHEX (val % 16);
                  *(strp2++) = isprint (val)? val : '.';
                }
              else
                {
                  *(strp++) = ' ';
                  *(strp++) = ' ';
                }
              if (j == 7)
                *(strp++) = ' ';
            }
          *(strp++) = ' ';
          *(strp2) = '\0';

          _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL, fmt, func, str);
        }
    }
  else
    {
      while (idx < len)
        {
          char str[48+4+1];
          char *strp = str;

          for (j = 0; j < 48; j++)
            {
              unsigned char val;
              if (idx < len)
                {
                  val = buffer[idx++];
                  if (val == '\n')
                    {
                      *strp++ = '<';
                      *strp++ = 'L';
                      *strp++ = 'F';
                      *strp++ = '>';
                      break;
                    }
                  *strp++ = (val > 31 && val < 127)? val : '.';
                }
            }
          *strp = 0;

          _gpgme_debug (NULL, lvl, -1, NULL, NULL, NULL, fmt, func, str);
        }
    }
}

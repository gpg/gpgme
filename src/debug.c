/* debug.c - helpful output in desperate situations
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2009 g10 Code GmbH

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
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
   MA 02110-1301, USA.  */

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

#include "util.h"
#include "ath.h"
#include "sema.h"
#include "sys-util.h"
#include "debug.h"


/* Lock to serialize initialization of the debug output subsystem and
   output of actual debug messages.  */
DEFINE_STATIC_LOCK (debug_lock);

/* The amount of detail requested by the user, per environment
   variable GPGME_DEBUG.  */
static int debug_level;

/* The output stream for the debug messages.  */
static FILE *errfp;

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


static void
debug_init (void)
{
  static int initialized;

  LOCK (debug_lock);
  if (!initialized)
    {
      gpgme_error_t err;
      char *e;
      const char *s1, *s2;;

      if (envvar_override)
        {
          e = strdup (envvar_override);
          free (envvar_override);
          envvar_override = NULL;
        }
      else
        {
#ifdef HAVE_W32CE_SYSTEM
          e = _gpgme_w32ce_get_debug_envvar ();
#else /*!HAVE_W32CE_SYSTEM*/
          err = _gpgme_getenv ("GPGME_DEBUG", &e);
          if (err)
            {
              UNLOCK (debug_lock);
              return;
            }
#endif /*!HAVE_W32CE_SYSTEM*/
        }

      initialized = 1;
      errfp = stderr;
      if (e)
	{
	  debug_level = atoi (e);
	  s1 = strchr (e, PATHSEP_C);
	  if (s1)
	    {
#ifndef HAVE_DOSISH_SYSTEM
	      if (getuid () == geteuid ()
#if defined(HAVE_GETGID) && defined(HAVE_GETEGID)
                  && getgid () == getegid ()
#endif
                  )
		{
#endif
		  char *p;
		  FILE *fp;

		  s1++;
		  if (!(s2 = strchr (s1, PATHSEP_C)))
		    s2 = s1 + strlen (s1);
		  p = malloc (s2 - s1 + 1);
		  if (p)
		    {
		      memcpy (p, s1, s2 - s1);
		      p[s2-s1] = 0;
		      trim_spaces (p);
		      fp = fopen (p,"a");
		      if (fp)
			{
			  setvbuf (fp, NULL, _IOLBF, 0);
			  errfp = fp;
			}
		      free (p);
		    }
#ifndef HAVE_DOSISH_SYSTEM
		}
#endif
	    }
	  free (e);
        }
    }
  UNLOCK (debug_lock);

  if (debug_level > 0)
    {
      _gpgme_debug (DEBUG_INIT, "gpgme_debug: level=%d\n", debug_level);
#ifdef HAVE_W32_SYSTEM
      {
        const char *name = _gpgme_get_inst_dir ();
        _gpgme_debug (DEBUG_INIT, "gpgme_debug: gpgme='%s'\n",
                      name? name: "?");
      }
#endif
    }
}



/* This should be called as soon as the locks are intialized.  It is
   required so that the assuan logging gets conncted to the gpgme log
   stream as early as possible.  */
void
_gpgme_debug_subsystem_init (void)
{
  debug_init ();
}




/* Log the formatted string FORMAT at debug level LEVEL or higher.
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
_gpgme_debug (int level, const char *format, ...)
{
  va_list arg_ptr;
  int saved_errno;

  saved_errno = errno;
  if (debug_level < level)
    return 0;

  va_start (arg_ptr, format);
  LOCK (debug_lock);
  {
#ifdef HAVE_W32CE_SYSTEM
    SYSTEMTIME t;

    GetLocalTime (&t);
    fprintf (errfp, "GPGME %04d-%02d-%02d %02d:%02d:%02d <0x%04llx>  ",
	     t.wYear, t.wMonth, t.wDay,
	     t.wHour, t.wMinute, t.wSecond,
	     (unsigned long long) ath_self ());
#else
    struct tm *tp;
    time_t atime = time (NULL);

    tp = localtime (&atime);
    fprintf (errfp, "GPGME %04d-%02d-%02d %02d:%02d:%02d <0x%04llx>  ",
	     1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
	     tp->tm_hour, tp->tm_min, tp->tm_sec,
	     (unsigned long long) ath_self ());
#endif
  }
#ifdef FRAME_NR
  {
    int indent;

    indent = frame_nr > 0? (2 * (frame_nr - 1)):0;
    fprintf (errfp, "%*s", indent < 40? indent : 40, "");
  }
#endif

  vfprintf (errfp, format, arg_ptr);
  va_end (arg_ptr);
  if(format && *format && format[strlen (format) - 1] != '\n')
    putc ('\n', errfp);
  UNLOCK (debug_lock);
  fflush (errfp);

  gpg_err_set_errno (saved_errno);
  return 0;
}


/* Start a new debug line in *LINE, logged at level LEVEL or higher,
   and starting with the formatted string FORMAT.  */
void
_gpgme_debug_begin (void **line, int level, const char *format, ...)
{
  va_list arg_ptr;
  int res;

  if (debug_level < level)
    {
      /* Disable logging of this line.  */
      *line = NULL;
      return;
    }

  va_start (arg_ptr, format);
  res = vasprintf ((char **) line, format, arg_ptr);
  va_end (arg_ptr);
  if (res < 0)
    *line = NULL;
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
  res = vasprintf (&toadd, format, arg_ptr);
  va_end (arg_ptr);
  if (res < 0)
    {
      free (*line);
      *line = NULL;
    }
  res = asprintf (&result, "%s%s", *(char **) line, toadd);
  free (toadd);
  free (*line);
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
  if (!*line)
    return;

  /* The smallest possible level is 1, so force logging here by
     using that.  */
  _gpgme_debug (1, "%s", *line);
  free (*line);
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
	      *(strp2++) = isprint (val) ? val : '.';
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

      _gpgme_debug (lvl, fmt, func, str);
    }
}

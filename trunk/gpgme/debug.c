/* debug.c - helpful output in desperate situations
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
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#ifndef HAVE_DOSISH_SYSTEM
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <fcntl.h>
#endif
#include <assert.h>

#include "util.h"
#include "sema.h"


/* Lock to serialize initialization of the debug output subsystem and
   output of actual debug messages.  */
DEFINE_STATIC_LOCK (debug_lock);

/* The amount of detail requested by the user, per environment
   variable GPGME_DEBUG.  */
static int debug_level;

/* The output stream for the debug messages.  */
static FILE *errfp;


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

      err = _gpgme_getenv ("GPGME_DEBUG", &e);
      if (err)
	{
	  UNLOCK (debug_lock);
	  return;
	}

      initialized = 1;
      errfp = stderr;
      if (e)
	{
	  debug_level = atoi (e);
	  s1 = strchr (e, ':');
	  if (s1)
	    {
#ifndef HAVE_DOSISH_SYSTEM
	      if (getuid () == geteuid ())
		{
#endif
		  char *p;
		  FILE *fp;

		  s1++;
		  if (!(s2 = strchr (s1, ':')))
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

      if (debug_level > 0)
	fprintf (errfp, "gpgme_debug: level=%d\n", debug_level);
    }
  UNLOCK (debug_lock);
}


/* Log the formatted string FORMAT at debug level LEVEL or higher.  */
void
_gpgme_debug (int level, const char *format, ...)
{
  va_list arg_ptr;

  debug_init ();
  if (debug_level < level)
    return;
    
  va_start (arg_ptr, format);
  LOCK (debug_lock);
  vfprintf (errfp, format, arg_ptr);
  va_end (arg_ptr);
  if(format && *format && format[strlen (format) - 1] != '\n')
    putc ('\n', errfp);
  UNLOCK (debug_lock);
  fflush (errfp);
}


/* Start a new debug line in *LINE, logged at level LEVEL or higher,
   and starting with the formatted string FORMAT.  */
void
_gpgme_debug_begin (void **line, int level, const char *format, ...)
{
  va_list arg_ptr;

  debug_init ();
  if (debug_level < level)
    {
      /* Disable logging of this line.  */
      *line = NULL;
      return;
    }

  va_start (arg_ptr, format);
  vasprintf ((char **) line, format, arg_ptr);
  va_end (arg_ptr);
}


/* Add the formatted string FORMAT to the debug line *LINE.  */
void
_gpgme_debug_add (void **line, const char *format, ...)
{
  va_list arg_ptr;
  char *toadd;
  char *result;

  if (!*line)
    return;

  va_start (arg_ptr, format);
  vasprintf (&toadd, format, arg_ptr);
  va_end (arg_ptr);
  asprintf (&result, "%s%s", *(char **) line, toadd);
  free (*line);
  free (toadd);
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

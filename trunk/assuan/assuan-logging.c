/* assuan-logging.c - Default logging function.
 *	Copyright (C) 2002, 2003, 2004 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA. 
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif /*HAVE_W32_SYSTEM*/
#include <errno.h>
#include <ctype.h>

#include "assuan-defs.h"

static char prefix_buffer[80];
static FILE *_assuan_log;
static int full_logging;

void
_assuan_set_default_log_stream (FILE *fp)
{
  if (!_assuan_log)
    {
      _assuan_log = fp;
      full_logging = !!getenv ("ASSUAN_FULL_LOGGING");
    }
}

void
assuan_set_assuan_log_stream (FILE *fp)
{
  _assuan_log = fp;
}


/* Set the per context log stream.  Also enable the default log stream
   if it has not been set.  */
void
assuan_set_log_stream (assuan_context_t ctx, FILE *fp)
{
  if (ctx)
    {
      if (ctx->log_fp)
        fflush (ctx->log_fp);
      ctx->log_fp = fp;
      _assuan_set_default_log_stream (fp);
    }
}


FILE *
assuan_get_assuan_log_stream (void)
{
  return _assuan_log ? _assuan_log : stderr;
}


/* Set the prefix to be used for logging to TEXT or
   resets it to the default if TEXT is NULL. */
void
assuan_set_assuan_log_prefix (const char *text)
{
  if (text)
    {
      strncpy (prefix_buffer, text, sizeof (prefix_buffer)-1);
      prefix_buffer[sizeof (prefix_buffer)-1] = 0;
    }
  else
    *prefix_buffer = 0;
}

const char *
assuan_get_assuan_log_prefix (void)
{
  return prefix_buffer;
}


void
_assuan_log_printf (const char *format, ...)
{
  va_list arg_ptr;
  FILE *fp;
  const char *prf;
  int save_errno = errno;
  
  fp = assuan_get_assuan_log_stream ();
  prf = assuan_get_assuan_log_prefix ();
  if (*prf)
    fprintf (fp, "%s[%u]: ", prf, (unsigned int)getpid ());

  va_start (arg_ptr, format);
  vfprintf (fp, format, arg_ptr );
  va_end (arg_ptr);
  errno = save_errno;
}


/* Dump a possibly binary string (used for debugging).  Distinguish
   ascii text from binary and print it accordingly.  This function
   takes FILE pointer arg becuase logging may be enabled on a per
   context basis. */
void
_assuan_log_print_buffer (FILE *fp, const void *buffer, size_t length)
{
  const unsigned char *s;
  int n;

  for (n=length,s=buffer; n; n--, s++)
    if  ((!isascii (*s) || iscntrl (*s) || !isprint (*s)) && !(*s >= 0x80))
      break;

  s = buffer;
  if (!n && *s != '[')
    fwrite (buffer, length, 1, fp);
  else
    {
#ifdef HAVE_FLOCKFILE
      flockfile (fp);
#endif
      putc_unlocked ('[', fp);
      if ( length > 16 && !full_logging)
        {
          for (n=0; n < 12; n++, s++)
            fprintf (fp, " %02x", *s);
          fprintf (fp, " ...(%d bytes skipped)", (int)length - 12);
        }
      else
        {
          for (n=0; n < length; n++, s++)
            fprintf (fp, " %02x", *s);
        }
      putc_unlocked (' ', fp);
      putc_unlocked (']', fp);
#ifdef HAVE_FUNLOCKFILE
      funlockfile (fp);
#endif
    }
}

/* Log a user supplied string.  Escapes non-printable before
   printing.  */
void
_assuan_log_sanitized_string (const char *string)
{
  const unsigned char *s = (const unsigned char *) string;
  FILE *fp = assuan_get_assuan_log_stream ();

  if (! *s)
    return;

#ifdef HAVE_FLOCKFILE
  flockfile (fp);
#endif

  for (; *s; s++)
    {
      int c = 0;

      switch (*s)
	{
	case '\r':
	  c = 'r';
	  break;

	case '\n':
	  c = 'n';
	  break;

	case '\f':
	  c = 'f';
	  break;

	case '\v':
	  c = 'v';
	  break;

	case '\b':
	  c = 'b';
	  break;

	default:
	  if ((isascii (*s) && isprint (*s)) || (*s >= 0x80))
	    putc_unlocked (*s, fp);
	  else
	    {
	      putc_unlocked ('\\', fp);
	      fprintf (fp, "x%02x", *s);
	    }
	}

      if (c)
	{
	  putc_unlocked ('\\', fp);
	  putc_unlocked (c, fp);
	}
    }

#ifdef HAVE_FUNLOCKFILE
  funlockfile (fp);
#endif
}



#ifdef HAVE_W32_SYSTEM
const char *
_assuan_w32_strerror (int ec)
{
  static char strerr[256];
  
  if (ec == -1)
    ec = (int)GetLastError ();
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM, NULL, ec,
                 MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
                 strerr, sizeof (strerr)-1, NULL);
  return strerr;    
}
#endif /*HAVE_W32_SYSTEM*/

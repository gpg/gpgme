/* conversion.c - String conversion helper functions.
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002, 2003 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "gpgme.h"
#include "util.h"

#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))


int
_gpgme_hextobyte (const byte *str)
{
  int val = 0;
  int i;

#define NROFHEXDIGITS 2
  for (i = 0; i < NROFHEXDIGITS; i++)
    {
      if (*str >= '0' && *str <= '9')
	val += *str - '0';
      else if (*str >= 'A' && *str <= 'F')
	val += 10 + *str - 'A';
      else if (*str >= 'a' && *str <= 'f')
	val += 10 + *str - 'a';
      else
	return -1;
      if (i < NROFHEXDIGITS - 1)
	val *= 16;
      str++;
    }
  return val;
}


GpgmeError
_gpgme_decode_c_string (const char *src, char **destp)
{
  char *dest;

  /* We can malloc a buffer of the same length, because the converted
     string will never be larger.  */
  dest = xtrymalloc (strlen (src) + 1);
  if (!dest)
    return mk_error (Out_Of_Core);

  *destp = dest;

  while (*src)
    {
      if (*src != '\\')
	*(dest++) = *(src++);
      else if (src[1] == '\\')
	{
	  src++;
	  *(dest++) = *(src++); 
        }
      else if (src[1] == 'n')
	{
	  src += 2;
	  *(dest++) = '\n'; 
        }
      else if (src[1] == 'r')
	{
	  src += 2;
	  *(dest++) = '\r'; 
        }
      else if (src[1] == 'v')
	{
	  src += 2;
	  *(dest++) = '\v'; 
        }
      else if (src[1] == 'b')
	{
	  src += 2;
	  *(dest++) = '\b'; 
        }
      else if (src[1] == '0')
	{
	  /* Hmmm: no way to express this */
	  src += 2;
	  *(dest++) = '\\';
	  *(dest++) = '\0'; 
        }
      else if (src[1] == 'x' && isxdigit (src[2]) && isxdigit (src[3]))
	{
	  int val = _gpgme_hextobyte (&src[2]);
	  if (val == -1)
	    {
	      /* Should not happen.  */
	      *(dest++) = *(src++);
	      *(dest++) = *(src++);
	      *(dest++) = *(src++);
	      *(dest++) = *(src++);
	    }
	  else
	    {
	      if (!val)
		{
		  *(dest++) = '\\';
		  *(dest++) = '\0'; 
		}
	      else 
		*(byte*)dest++ = val;
	      src += 4;
	    }
        }
      else
	{
	  /* should not happen */
	  src++;
	  *(dest++) = '\\'; 
	  *(dest++) = *(src++);
        } 
    }
  *(dest++) = 0;

  return 0;
}


time_t
_gpgme_parse_timestamp (const char *timestamp)
{
  /* Need toskip leading spaces, becuase that is what strtoul does but
     not our ISO 8601 checking code. */
  while (*timestamp && *timestamp== ' ')
    timestamp++;
  if (!*timestamp)
    return 0;

  if (strlen (timestamp) >= 15 && timestamp[8] == 'T')
    {
      struct tm buf;
      int year;

      year = atoi_4 (timestamp);
      if (year < 1900)
        return (time_t)(-1);

      /* Fixme: We would better use a configure test to see whether
         mktime can handle dates beyond 2038. */
      if (sizeof (time_t) <= 4 && year >= 2038)
        return (time_t)2145914603; /* 2037-12-31 23:23:23 */

      memset (&buf, 0, sizeof buf);
      buf.tm_year = year - 1900;
      buf.tm_mon = atoi_2 (timestamp+4) - 1; 
      buf.tm_mday = atoi_2 (timestamp+6);
      buf.tm_hour = atoi_2 (timestamp+9);
      buf.tm_min = atoi_2 (timestamp+11);
      buf.tm_sec = atoi_2 (timestamp+13);

#ifdef HAVE_TIMEGM
      return timegm (&buf);
#else
      {
        time_t tim;
        
        putenv ("TZ=UTC");
        tim = mktime (&buf);
#ifdef __GNUC__
#warning fixme: we must somehow reset TZ here.  It is not threadsafe anyway.
#endif
        return tim;
      }
#endif /* !HAVE_TIMEGM */
    }
  else
    return (time_t)strtoul (timestamp, NULL, 10);
}


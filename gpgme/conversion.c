/* conversion.c - String conversion helper functions.
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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

#include <ctype.h>
#include "gpgme.h"
#include "util.h"


int
_gpgme_hextobyte (const byte *str)
{
  int val = 0;
  int i;

  for (i = 0; i < 2; i++)
    {
      if (*str >= '0' && *str <= '9')
	val += *str - '0';
      else if (*str >= 'A' && *str <= 'F')
	val += 10 + *str - 'A';
      else if (*str >= 'a' && *str <= 'f')
	val += 10 + *str - 'a';
      else
	return -1;
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
  *destp = dest;

  return 0;
}

/* conversion.c - String conversion helper functions.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH
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
#ifdef HAVE_SYS_TYPES_H
  /* Solaris 8 needs sys/types.h before time.h.  */
# include <sys/types.h>
#endif
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>

#include "gpgme.h"
#include "util.h"
#include "debug.h"

#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')



void
_gpgme_wipememory (void *ptr, size_t len)
{
  /* Prevent compiler from optimizing away the call to memset by accessing
   * memset through volatile pointer. */
  static void *(*volatile memset_ptr)(void *, int, size_t) = (void *)memset;
  memset_ptr (ptr, 0, len);
}



static char *
do_strconcat (const char *s1, va_list arg_ptr)
{
  const char *argv[16];
  size_t argc;
  size_t needed;
  char *buffer, *p;

  argc = 0;
  argv[argc++] = s1;
  needed = strlen (s1);
  while (((argv[argc] = va_arg (arg_ptr, const char *))))
    {
      needed += strlen (argv[argc]);
      if (argc >= DIM (argv)-1)
        {
          gpg_err_set_errno (EINVAL);
          return NULL;
        }
      argc++;
    }
  needed++;
  buffer = malloc (needed);
  if (buffer)
    {
      for (p = buffer, argc=0; argv[argc]; argc++)
        p = stpcpy (p, argv[argc]);
    }
  return buffer;
}


/* Concatenate the string S1 with all the following strings up to a
 * NULL.  Returns a malloced buffer with the new string or NULL on a
   malloc error or if too many arguments are given.  */
char *
_gpgme_strconcat (const char *s1, ...)
{
  va_list arg_ptr;
  char *result;

  if (!s1)
    result = strdup ("");
  else
    {
      va_start (arg_ptr, s1);
      result = do_strconcat (s1, arg_ptr);
      va_end (arg_ptr);
    }
  return result;
}




/* Convert two hexadecimal digits from STR to the value they
   represent.  Returns -1 if one of the characters is not a
   hexadecimal digit.  */
int
_gpgme_hextobyte (const char *str)
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


/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
gpgme_error_t
_gpgme_decode_c_string (const char *src, char **destp, size_t len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return gpg_error (GPG_ERR_INTERNAL);

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return gpg_error_from_syserror ();

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src != '\\')
	{
	  *(dest++) = *(src++);
	  continue;
	}

      switch (src[1])
	{
#define DECODE_ONE(match,result)	\
	case match:			\
	  src += 2;			\
	  *(dest++) = result;		\
	  break;

	  DECODE_ONE ('\'', '\'');
	  DECODE_ONE ('\"', '\"');
	  DECODE_ONE ('\?', '\?');
	  DECODE_ONE ('\\', '\\');
	  DECODE_ONE ('a', '\a');
	  DECODE_ONE ('b', '\b');
	  DECODE_ONE ('f', '\f');
	  DECODE_ONE ('n', '\n');
	  DECODE_ONE ('r', '\r');
	  DECODE_ONE ('t', '\t');
	  DECODE_ONE ('v', '\v');

	case 'x':
	  {
	    int val = _gpgme_hextobyte (&src[2]);

	    if (val == -1)
	      {
		/* Should not happen.  */
		*(dest++) = *(src++);
		*(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
	      }
	    else
	      {
		if (!val)
		  {
		    /* A binary zero is not representable in a C
		       string.  */
		    *(dest++) = '\\';
		    *(dest++) = '0';
		  }
		else
		  *((unsigned char *) dest++) = val;
		src += 4;
	      }
	  }
	  break;

	default:
	  {
	    /* Should not happen.  */
	    *(dest++) = *(src++);
	    *(dest++) = *(src++);
	  }
        }
    }
  *(dest++) = 0;

  return 0;
}


/* Decode the percent escaped string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  If BINARY is 1, then '\0'
   characters are allowed in the output.  */
gpgme_error_t
_gpgme_decode_percent_string (const char *src, char **destp, size_t len,
			      int binary)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return gpg_error (GPG_ERR_INTERNAL);

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return gpg_error_from_syserror ();

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src != '%')
	{
	  *(dest++) = *(src++);
	  continue;
	}
      else
	{
	  int val = _gpgme_hextobyte (&src[1]);

	  if (val == -1)
	    {
	      /* Should not happen.  */
	      *(dest++) = *(src++);
	      if (*src)
		*(dest++) = *(src++);
	      if (*src)
		*(dest++) = *(src++);
	    }
	  else
	    {
	      if (!val && !binary)
		{
		  /* A binary zero is not representable in a C
		     string.  */
		  *(dest++) = '\\';
		  *(dest++) = '0';
		}
	      else
		*((unsigned char *) dest++) = val;
	      src += 3;
	    }
	}
    }
  *(dest++) = 0;

  return 0;
}


/* Encode the string SRC with percent escaping and store the result in
   the buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  If BINARY is 1, then '\0'
   characters are allowed in the output.  */
gpgme_error_t
_gpgme_encode_percent_string (const char *src, char **destp, size_t len)
{
  size_t destlen;
  char *dest;
  const char *str;

  destlen = 0;
  str = src;
  /* We percent-escape the + character because the user might need a
     "percent plus" escaped string (special gpg format).  But we
     percent-escape the space character, which works with and without
     the special plus format.  */
  while (*str)
    {
      if (*str == '+' || *str == '\"' || *str == '%'
          || *(const unsigned char *)str <= 0x20)
        destlen += 3;
      else
        destlen++;
      str++;
    }
  /* Terminating nul byte.  */
  destlen++;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < destlen)
	return gpg_error (GPG_ERR_INTERNAL);

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (destlen);
      if (!dest)
	return gpg_error_from_syserror ();

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src == '+' || *src == '\"' || *src == '%'
          || *(const unsigned char *)src <= 0x20)
        {
          snprintf (dest, 4, "%%%02X", *(unsigned char *)src);
	  dest += 3;
	}
      else
	*(dest++) = *src;
      src++;
    }
  *(dest++) = 0;

  return 0;
}


/* Split a string into space delimited fields and remove leading and
 * trailing spaces from each field.  A pointer to each field is
 * stored in ARRAY.  Stop splitting at ARRAYSIZE fields.  The function
 * modifies STRING.  The number of parsed fields is returned.
 */
int
_gpgme_split_fields (char *string, char **array, int arraysize)
{
  int n = 0;
  char *p, *pend;

  for (p = string; *p == ' '; p++)
    ;
  do
    {
      if (n == arraysize)
        break;
      array[n++] = p;
      pend = strchr (p, ' ');
      if (!pend)
        break;
      *pend++ = 0;
      for (p = pend; *p == ' '; p++)
        ;
    }
  while (*p);

  return n;
}


/* Tokenize STRING using the set of delimiters in DELIM into a NULL
 * delimited array.  Leading spaces and tabs are removed from all
 * tokens if TRIM is set.  The caller must free the result.
 *
 * Returns: A malloced and NULL delimited array with the tokens.  On
 *          memory error NULL is returned and ERRNO is set.
 */
char **
_gpgme_strtokenize (const char *string, const char *delim, int trim)
{
  const char *s;
  size_t fields;
  size_t bytes, n;
  char *buffer;
  char *p, *px, *pend;
  char **result;

  /* Count the number of fields.  */
  for (fields = 1, s = strpbrk (string, delim); s; s = strpbrk (s + 1, delim))
    fields++;
  fields++; /* Add one for the terminating NULL.  */

  /* Allocate an array for all fields, a terminating NULL, and space
     for a copy of the string.  */
  bytes = fields * sizeof *result;
  if (bytes / sizeof *result != fields)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  n = strlen (string) + 1;
  bytes += n;
  if (bytes < n)
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  result = malloc (bytes);
  if (!result)
    return NULL;
  buffer = (char*)(result + fields);

  /* Copy and parse the string.  */
  strcpy (buffer, string);
  for (n = 0, p = buffer; (pend = strpbrk (p, delim)); p = pend + 1)
    {
      *pend = 0;
      if (trim)
        {
          while (spacep (p))
            p++;
          for (px = pend - 1; px >= p && spacep (px); px--)
            *px = 0;
        }
      result[n++] = p;
    }
  if (trim)
    {
      while (spacep (p))
        p++;
      for (px = p + strlen (p) - 1; px >= p && spacep (px); px--)
        *px = 0;
    }
  result[n++] = p;
  result[n] = NULL;

  assert ((char*)(result + n + 1) == buffer);

  return result;
}


/* Convert the field STRING into an unsigned long value.  Check for
 * trailing garbage.  */
gpgme_error_t
_gpgme_strtoul_field (const char *string, unsigned long *result)
{
  char *endp;

  gpg_err_set_errno (0);
  *result = strtoul (string, &endp, 0);
  if (errno)
    return gpg_error_from_syserror ();
  if (endp == string || *endp)
    return gpg_error (GPG_ERR_INV_VALUE);
  return 0;
}


/* Convert STRING into an offset value.  Note that this functions only
 * allows for a base-10 length.  This function is similar to atoi()
 * and thus there is no error checking.  */
uint64_t
_gpgme_string_to_off (const char *string)
{
  uint64_t value = 0;

  while (*string == ' ' || *string == '\t')
    string++;
  for (; *string >= '0' && *string <= '9'; string++)
    {
      value *= 10;
      value += atoi_1 (string);
    }
  return value;
}


#ifdef HAVE_W32_SYSTEM
static time_t
_gpgme_timegm (struct tm *tm)
{
  /* This one is thread safe.  */
  SYSTEMTIME st;
  FILETIME ft;
  unsigned long long cnsecs;

  st.wYear   = tm->tm_year + 1900;
  st.wMonth  = tm->tm_mon  + 1;
  st.wDay    = tm->tm_mday;
  st.wHour   = tm->tm_hour;
  st.wMinute = tm->tm_min;
  st.wSecond = tm->tm_sec;
  st.wMilliseconds = 0; /* Not available.  */
  st.wDayOfWeek = 0;    /* Ignored.  */

  /* System time is UTC thus the conversion is pretty easy.  */
  if (!SystemTimeToFileTime (&st, &ft))
    {
      gpg_err_set_errno (EINVAL);
      return (time_t)(-1);
    }

  cnsecs = (((unsigned long long)ft.dwHighDateTime << 32)
	    | ft.dwLowDateTime);
  cnsecs -= 116444736000000000ULL; /* The filetime epoch is 1601-01-01.  */
  return (time_t)(cnsecs / 10000000ULL);
}
#endif


/* Parse the string TIMESTAMP into a time_t.  The string may either be
   seconds since Epoch or in the ISO 8601 format like
   "20390815T143012".  Returns 0 for an empty string or seconds since
   Epoch. Leading spaces are skipped. If ENDP is not NULL, it will
   point to the next non-parsed character in TIMESTRING. */
time_t
_gpgme_parse_timestamp (const char *timestamp, char **endp)
{
  /* Need to skip leading spaces, because that is what strtoul does
     but not our ISO 8601 checking code. */
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

      if (endp)
        *endp = (char*)(timestamp + 15);

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

#ifdef HAVE_W32_SYSTEM
      return _gpgme_timegm (&buf);
#else
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
#endif /* !HAVE_W32_SYSTEM */
    }
  else
    return (time_t)strtoul (timestamp, endp, 10);
}


/* This function is similar to _gpgme_parse_timestamp but returns an
 * unsigned long and 0 on error.  */
unsigned long
_gpgme_parse_timestamp_ul (const char *timestamp)
{
  time_t tim;
  char *tail;

  if (!*timestamp)
    return 0; /* Shortcut empty strings.  */

  tim = _gpgme_parse_timestamp (timestamp, &tail);
  if (tim == -1 || timestamp == tail || (*tail && *tail != ' '))
    tim = 0; /* No time given or invalid engine.  */

  return (unsigned long)tim;
}


/* The GPG backend uses OpenPGP algorithm numbers which we need to map
   to our algorithm numbers.  This function MUST not change ERRNO. */
int
_gpgme_map_pk_algo (int algo, gpgme_protocol_t protocol)
{
  if (protocol == GPGME_PROTOCOL_OPENPGP)
    {
      switch (algo)
        {
        case 1: case 2: case 3: case 16: case 17: break;
        case 18: algo = GPGME_PK_ECDH; break;
        case 19: algo = GPGME_PK_ECDSA; break;
        case 20: break;
        case 22: algo = GPGME_PK_EDDSA; break;
        default: algo = 0; break; /* Unknown.  */
        }
    }

  return algo;
}


/* Return a string with a cipher algorithm.  */
const char *
_gpgme_cipher_algo_name (int algo, gpgme_protocol_t protocol)
{
  if (protocol == GPGME_PROTOCOL_OPENPGP)
    {
      /* The algo is given according to OpenPGP specs.  */
      switch (algo)
        {
        case 1:  return "IDEA";
        case 2:	 return "3DES";
        case 3:	 return "CAST5";
        case 4:  return "BLOWFISH";
        case 7:  return "AES";
        case 8:  return "AES192";
        case 9:  return "AES256";
        case 10: return "TWOFISH";
        case 11: return "CAMELLIA128";
        case 12: return "CAMELLIA192";
        case 13: return "CAMELLIA256";
        }
    }

  return "Unknown";
}


/* Return a string with the cipher mode.  */
const char *
_gpgme_cipher_mode_name (int algo, gpgme_protocol_t protocol)
{
  if (protocol == GPGME_PROTOCOL_OPENPGP)
    {
      /* The algo is given according to OpenPGP specs.  */
      switch (algo)
        {
        case 0:  return "CFB";
        case 1:  return "EAX";
        case 2:	 return "OCB";
        }
    }

  return "Unknown";
}


/* Replace all backslashes with forward slashes.  */
void
_gpgme_replace_backslashes (char *string)
{
  for (; *string; string++)
    if (*string == '\\')
      *string = '/';
}

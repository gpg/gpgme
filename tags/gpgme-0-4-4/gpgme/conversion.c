/* conversion.c - String conversion helper functions.
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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "gpgme.h"
#include "util.h"


#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))



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
	return gpg_error_from_errno (errno);

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
   is large enough if LEN is not zero.  */
gpgme_error_t
_gpgme_decode_percent_string (const char *src, char **destp, size_t len)
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
	return gpg_error_from_errno (errno);

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
	      if (!val)
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

      if (endp)
        *endp = (char*)(timestamp + 15);
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
    return (time_t)strtoul (timestamp, endp, 10);
}




static struct
{
  char *name;
  gpgme_error_t err;
} gnupg_errors[] =
  {
    { "EOF", GPG_ERR_EOF },
    { "No_Error", GPG_ERR_NO_ERROR },
    { "General_Error", GPG_ERR_GENERAL },
    { "Out_Of_Core", GPG_ERR_ENOMEM },
    { "Invalid_Value", GPG_ERR_INV_VALUE },
    { "IO_Error", GPG_ERR_GENERAL },
    { "Resource_Limit", GPG_ERR_RESOURCE_LIMIT },
    { "Internal_Error", GPG_ERR_INTERNAL },
    { "Bad_Certificate", GPG_ERR_BAD_CERT },
    { "Bad_Certificate_Chain", GPG_ERR_BAD_CERT_CHAIN},
    { "Missing_Certificate", GPG_ERR_MISSING_CERT },
    { "No_Data", GPG_ERR_NO_DATA },
    { "Bad_Signature", GPG_ERR_BAD_SIGNATURE },
    { "Not_Implemented", GPG_ERR_NOT_IMPLEMENTED },
    { "Conflict", GPG_ERR_CONFLICT },
    { "Bug", GPG_ERR_BUG },
    { "Read_Error", GPG_ERR_GENERAL },
    { "Write_Error", GPG_ERR_GENERAL },
    { "Invalid_Line", GPG_ERR_GENERAL },
    { "Incomplete_Line", GPG_ERR_INCOMPLETE_LINE },
    { "Invalid_Response", GPG_ERR_INV_RESPONSE },
    { "Agent_Error", GPG_ERR_AGENT },
    { "No_Public_Key", GPG_ERR_NO_PUBKEY },
    { "No_Secret_Key", GPG_ERR_NO_SECKEY },
    { "File_Open_Error", GPG_ERR_GENERAL },
    { "File_Create_Error", GPG_ERR_GENERAL },
    { "File_Error", GPG_ERR_GENERAL },
    { "Not_Supported", GPG_ERR_NOT_SUPPORTED },
    { "Invalid_Data", GPG_ERR_INV_DATA },
    { "Assuan_Server_Fault", GPG_ERR_ASSUAN_SERVER_FAULT },
    { "Assuan_Error", GPG_ERR_ASSUAN },
    { "Invalid_Session_Key", GPG_ERR_INV_SESSION_KEY },
    { "Invalid_Sexp", GPG_ERR_INV_SEXP },
    { "Unsupported_Algorithm", GPG_ERR_UNSUPPORTED_ALGORITHM },
    { "No_PIN_Entry", GPG_ERR_NO_PIN_ENTRY },
    { "PIN_Entry_Error", GPG_ERR_NO_PIN_ENTRY },
    { "Bad_PIN", GPG_ERR_BAD_PIN },
    { "Bad_Passphrase", GPG_ERR_BAD_PASSPHRASE },
    { "Invalid_Name", GPG_ERR_INV_NAME },
    { "Bad_Public_Key", GPG_ERR_BAD_PUBKEY },
    { "Bad_Secret_Key", GPG_ERR_BAD_SECKEY },
    { "Bad_Data", GPG_ERR_BAD_DATA },
    { "Invalid_Parameter", GPG_ERR_INV_PARAMETER },
    { "Tribute_to_D_A", GPG_ERR_TRIBUTE_TO_D_A },
    { "No_Dirmngr", GPG_ERR_NO_DIRMNGR },
    { "Dirmngr_Error", GPG_ERR_DIRMNGR },
    { "Certificate_Revoked", GPG_ERR_CERT_REVOKED },
    { "No_CRL_Known", GPG_ERR_NO_CRL_KNOWN },
    { "CRL_Too_Old", GPG_ERR_CRL_TOO_OLD },
    { "Line_Too_Long", GPG_ERR_LINE_TOO_LONG },
    { "Not_Trusted", GPG_ERR_NOT_TRUSTED },
    { "Canceled", GPG_ERR_CANCELED },
    { "Bad_CA_Certificate", GPG_ERR_BAD_CA_CERT },
    { "Certificate_Expired", GPG_ERR_CERT_EXPIRED },
    { "Certificate_Too_Young", GPG_ERR_CERT_TOO_YOUNG },
    { "Unsupported_Certificate", GPG_ERR_UNSUPPORTED_CERT },
    { "Unknown_Sexp", GPG_ERR_UNKNOWN_SEXP },
    { "Unsupported_Protection", GPG_ERR_UNSUPPORTED_PROTECTION },
    { "Corrupted_Protection", GPG_ERR_CORRUPTED_PROTECTION },
    { "Ambiguous_Name", GPG_ERR_AMBIGUOUS_NAME },
    { "Card_Error", GPG_ERR_CARD },
    { "Card_Reset", GPG_ERR_CARD_RESET },
    { "Card_Removed", GPG_ERR_CARD_REMOVED },
    { "Invalid_Card", GPG_ERR_INV_CARD },
    { "Card_Not_Present", GPG_ERR_CARD_NOT_PRESENT },
    { "No_PKCS15_App", GPG_ERR_NO_PKCS15_APP },
    { "Not_Confirmed", GPG_ERR_NOT_CONFIRMED },
    { "Configuration_Error", GPG_ERR_CONFIGURATION },
    { "No_Policy_Match", GPG_ERR_NO_POLICY_MATCH },
    { "Invalid_Index", GPG_ERR_INV_INDEX },
    { "Invalid_Id", GPG_ERR_INV_ID },
    { "No_Scdaemon", GPG_ERR_NO_SCDAEMON },
    { "Scdaemon_Error", GPG_ERR_SCDAEMON },
    { "Unsupported_Protocol", GPG_ERR_UNSUPPORTED_PROTOCOL },
    { "Bad_PIN_Method", GPG_ERR_BAD_PIN_METHOD },
    { "Card_Not_Initialized", GPG_ERR_CARD_NOT_INITIALIZED },
    { "Unsupported_Operation", GPG_ERR_UNSUPPORTED_OPERATION },
    { "Wrong_Key_Usage", GPG_ERR_WRONG_KEY_USAGE }
  };
    

gpgme_error_t
_gpgme_map_gnupg_error (char *err)
{
  unsigned int i;

  for (i = 0; i < DIM (gnupg_errors); i++)
    if (!strcmp (gnupg_errors[i].name, err))
      return gpg_err_make (GPG_ERR_SOURCE_GPG, gnupg_errors[i].err);

  return gpg_err_make (GPG_ERR_SOURCE_GPG, GPG_ERR_GENERAL);
}

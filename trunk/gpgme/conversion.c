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

#include "gpgme.h"
#include "util.h"


/* Convert two hexadecimal digits from STR to the value they
   represent.  Returns -1 if one of the characters is not a
   hexadecimal digit.  */
int
_gpgme_hextobyte (const unsigned char *str)
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
_gpgme_decode_c_string (const char *src, char **destp, int len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return GPGME_General_Error;

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return GPGME_Out_Of_Core;

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
_gpgme_decode_percent_string (const char *src, char **destp, int len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return GPGME_General_Error;

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return GPGME_Out_Of_Core;

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


static struct
{
  char *name;
  gpgme_error_t err;
} gnupg_errors[] =
  {
    { "EOF", GPGME_EOF },
    { "No_Error", GPGME_No_Error },
    { "General_Error", GPGME_General_Error },
    { "Out_Of_Core", GPGME_Out_Of_Core },
    { "Invalid_Value", GPGME_Invalid_Value },
    { "IO_Error", GPGME_General_Error },
    { "Resource_Limit", GPGME_General_Error },
    { "Internal_Error", GPGME_General_Error },
    { "Bad_Certificate", GPGME_Invalid_Key },
    { "Bad_Certificate_Chain", GPGME_General_Error },
    { "Missing_Certificate", GPGME_No_Public_Key },
    { "No_Data", GPGME_No_Data },
    { "Bad_Signature", GPGME_Bad_Signature },
    { "Not_Implemented", GPGME_Not_Implemented },
    { "Conflict", GPGME_Conflict },
    { "Bug", GPGME_General_Error },
    { "Read_Error", GPGME_General_Error },
    { "Write_Error", GPGME_General_Error },
    { "Invalid_Line", GPGME_General_Error },
    { "Incomplete_Line", GPGME_General_Error },
    { "Invalid_Response", GPGME_General_Error },
    { "Agent_Error", GPGME_General_Error },
    { "No_Public_Key", GPGME_No_Public_Key },
    { "No_Secret_Key", GPGME_No_Secret_Key },
    { "File_Open_Error", GPGME_General_Error },
    { "File_Create_Error", GPGME_General_Error },
    { "File_Error", GPGME_General_Error },
    { "Not_Supported", GPGME_General_Error },
    { "Invalid_Data", GPGME_General_Error },
    { "Assuan_Server_Fault", GPGME_General_Error },
    { "Assuan_Error", GPGME_General_Error },
    { "Invalid_Session_Key", GPGME_General_Error },
    { "Invalid_Sexp", GPGME_General_Error },
    { "Unsupported_Algorithm", GPGME_Unsupported_Algorithm },
    { "No_PIN_Entry", GPGME_Invalid_Engine },
    { "PIN_Entry_Error", GPGME_Invalid_Engine },
    { "Bad_PIN", GPGME_Bad_Passphrase },
    { "Bad_Passphrase", GPGME_Bad_Passphrase },
    { "Invalid_Name", GPGME_General_Error },
    { "Bad_Public_Key", GPGME_General_Error },
    { "Bad_Secret_Key", GPGME_General_Error },
    { "Bad_Data", GPGME_General_Error },
    { "Invalid_Parameter", GPGME_General_Error },
    { "Tribute_to_D_A", GPGME_General_Error },
    { "No_Dirmngr", GPGME_Invalid_Engine },
    { "Dirmngr_Error", GPGME_General_Error },
    { "Certificate_Revoked", GPGME_Key_Revoked },
    { "No_CRL_Known", GPGME_No_CRL_Known },
    { "CRL_Too_Old", GPGME_CRL_Too_Old },
    { "Line_Too_Long", GPGME_General_Error },
    { "Not_Trusted", GPGME_Key_Not_Trusted },
    { "Canceled", GPGME_Canceled },
    { "Bad_CA_Certificate", GPGME_General_Error },
    { "Certificate_Expired", GPGME_Key_Expired },
    { "Certificate_Too_Young", GPGME_Invalid_Key },
    { "Unsupported_Certificate", GPGME_General_Error },
    { "Unknown_Sexp", GPGME_General_Error },
    { "Unsupported_Protection", GPGME_General_Error },
    { "Corrupted_Protection", GPGME_General_Error },
    { "Ambiguous_Name", GPGME_Ambiguous_Specification },
    { "Card_Error", GPGME_General_Error },
    { "Card_Reset", GPGME_General_Error },
    { "Card_Removed", GPGME_General_Error },
    { "Invalid_Card", GPGME_General_Error },
    { "Card_Not_Present", GPGME_General_Error },
    { "No_PKCS15_App", GPGME_General_Error },
    { "Not_Confirmed", GPGME_General_Error },
    { "Configuration_Error", GPGME_General_Error },
    { "No_Policy_Match", GPGME_Policy_Mismatch },
    { "Invalid_Index", GPGME_General_Error },
    { "Invalid_Id", GPGME_General_Error },
    { "No_Scdaemon", GPGME_Invalid_Engine },
    { "Scdaemon_Error", GPGME_General_Error },
    { "Unsupported_Protocol", GPGME_General_Error },
    { "Bad_PIN_Method", GPGME_General_Error },
    { "Card_Not_Initialized", GPGME_General_Error },
    { "Unsupported_Operation", GPGME_General_Error },
    { "Wrong_Key_Usage", GPGME_Wrong_Key_Usage }
  };
    

gpgme_error_t
_gpgme_map_gnupg_error (char *err)
{
  int i;

  for (i = 0; i < DIM (gnupg_errors); i++)
    if (!strcmp (gnupg_errors[i].name, err))
      return gnupg_errors[i].err;

  return GPGME_General_Error;
}

/* sig-notation.c - Signature notation data support.
   Copyright (C) 2005 g10 Code GmbH

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
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpgme.h"
#include "util.h"
#include "context.h"
#include "ops.h"
#include "debug.h"


/* Free the signature notation object and all associated resources.
   The object must already be removed from any linked list as the next
   pointer is ignored.  */
void
_gpgme_sig_notation_free (gpgme_sig_notation_t notation)
{
  if (notation->name)
    free (notation->name);

  if (notation->value)
    free (notation->value);

  free (notation);
}


/* Set the flags of NOTATION to FLAGS.  */
static void
sig_notation_set_flags (gpgme_sig_notation_t notation,
			gpgme_sig_notation_flags_t flags)
{
  /* We copy the flags into individual bits to make them easier
     accessible individually for the user.  */
  notation->human_readable = flags & GPGME_SIG_NOTATION_HUMAN_READABLE ? 1 : 0;
  notation->critical = flags & GPGME_SIG_NOTATION_CRITICAL ? 1 : 0;

  notation->flags = flags;
}


/* Create a new, empty signature notation data object.  */
gpgme_error_t
_gpgme_sig_notation_create (gpgme_sig_notation_t *notationp,
			    const char *name, int name_len,
			    const char *value, int value_len,
			    gpgme_sig_notation_flags_t flags)
{
  gpgme_error_t err = 0;
  gpgme_sig_notation_t notation;

  /* Currently, we require all notations to be human-readable.  */
  if (name && !(flags & GPGME_SIG_NOTATION_HUMAN_READABLE))
    return gpg_error (GPG_ERR_INV_VALUE);

  notation = calloc (1, sizeof (*notation));
  if (!notation)
    return gpg_error_from_syserror ();

  /* This is critical.  We want to reliably identify policy URLs by
     using a NULL pointer for NAME.  So all notations must have a NAME
     string, even if it is empty.  */
  if (name)
    {
      /* We add a trailing '\0' for stringification in the good
	 case.  */
      notation->name = malloc (name_len + 1);
      if (!notation->name)
	{
	  err = gpg_error_from_syserror ();
	  goto err;
	}

      memcpy (notation->name, name, name_len);
      notation->name[name_len] = '\0';
      notation->name_len = name_len;
    }

  if (value)
    {
      /* We add a trailing '\0' for stringification in the good
	 case.  */
      notation->value = malloc (value_len + 1);
      if (!notation->value)
	{
	  err = gpg_error_from_syserror ();
	  goto err;
	}

      memcpy (notation->value, value, value_len);
      notation->value[value_len] = '\0';
      notation->value_len = value_len;
    }

  sig_notation_set_flags (notation, flags);

  *notationp = notation;
  return 0;

 err:
  _gpgme_sig_notation_free (notation);
  return err;
}


/* GnuPG subpacket flags.  */

/* This subpacket data is part of the hashed data.  */
#define GNUPG_SPK_HASHED	0x01

/* This subpacket is marked critical.  */
#define GNUPG_SPK_CRITICAL	0x02

/* Parse a notation or policy URL subpacket.  If the packet type is
   not known, return no error but NULL in NOTATION.  */
gpgme_error_t
_gpgme_parse_notation (gpgme_sig_notation_t *notationp,
		       int type, int pkflags, int len, char *data)
{
  gpgme_error_t err;
  char *name = NULL;
  int name_len = 0;
  char *value = NULL;
  int value_len = 0;
  gpgme_sig_notation_flags_t flags = 0;
  char *decoded_data;
  unsigned char *bdata;

  /* Type 20: Notation data.  */
  /* Type 26: Policy URL.  */
  if (type != 20 && type != 26)
    {
      *notationp = NULL;
      return 0;
    }

  /* A few simple sanity checks.  */
  if (len > strlen (data))
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  /* See below for the format of a notation subpacket.  It has at
     least four octets of flags and two times two octets of length
     information.  */
  if (type == 20 && len < 4 + 2 + 2)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  err = _gpgme_decode_percent_string (data, &decoded_data, 0, 1);
  if (err)
    return err;
  bdata = (unsigned char *) decoded_data;

  /* Flags common to notation data and policy URL.  */
  if (pkflags & GNUPG_SPK_CRITICAL)
    flags |= GPGME_SIG_NOTATION_CRITICAL;

  /* This information is relevant in parsing multi-octet numbers below:

     3.1. Scalar numbers

     Scalar numbers are unsigned, and are always stored in big-endian
     format.  Using n[k] to refer to the kth octet being interpreted,
     the value of a two-octet scalar is ((n[0] << 8) + n[1]).  The
     value of a four-octet scalar is ((n[0] << 24) + (n[1] << 16) +
     (n[2] << 8) + n[3]).

     From RFC2440: OpenPGP Message Format.  Copyright (C) The Internet
     Society (1998).  All Rights Reserved.  */
#define RFC2440_GET_WORD(chr) ((((int)((unsigned char *)(chr))[0]) << 8) \
			       + ((int)((unsigned char *)(chr))[1]))

  if (type == 20)
    {
      /* 5.2.3.15. Notation Data

	 (4 octets of flags, 2 octets of name length (M),
	 2 octets of value length (N), M octets of name data,
	 N octets of value data)

	 [...] The "flags" field holds four octets of flags.
	 All undefined flags MUST be zero. Defined flags are:

	 First octet: 0x80 = human-readable. [...]
	 Other octets:  none.

	 From RFC2440: OpenPGP Message Format.  Copyright (C) The
	 Internet Society (1998).  All Rights Reserved.  */

      int chr;

      /* First octet of flags.  */
#define RFC2440_SPK20_FLAG1_HUMAN_READABLE 0x80

      chr = *bdata;
      bdata++;

      if (chr & RFC2440_SPK20_FLAG1_HUMAN_READABLE)
	flags |= GPGME_SIG_NOTATION_HUMAN_READABLE;

      /* The second, third and four octet of flags are unused.  */
      bdata++;
      bdata++;
      bdata++;

      name_len = RFC2440_GET_WORD (bdata);
      bdata += 2;

      value_len = RFC2440_GET_WORD (bdata);
      bdata += 2;

      /* Small sanity check.  */
      if (4 + 2 + 2 + name_len + value_len > len)
	{
	  free (decoded_data);
	  return trace_gpg_error (GPG_ERR_INV_ENGINE);
	}

      name = (char *) bdata;
      bdata += name_len;

      value = (char *) bdata;
    }
  else
    {
      /* Type is 26.  */

      /* NAME is NULL, name_len is 0.  */

      value = (char *) bdata;
      value_len = strlen (value);
    }

  err = _gpgme_sig_notation_create (notationp, name, name_len,
				    value, value_len, flags);

  free (decoded_data);
  return err;
}

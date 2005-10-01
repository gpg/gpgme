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
    return gpg_error_from_errno (errno);

  if (name_len)
    {
      /* We add a trailing '\0' for stringification in the good
	 case.  */
      notation->name = malloc (name_len + 1);
      if (!notation->name)
	{
	  err = gpg_error_from_errno (errno);
	  goto err;
	}

      memcpy (notation->name, name, name_len);
      notation->name[name_len] = '\0';
      notation->name_len = name_len;
    }

  if (value_len)
    {
      /* We add a trailing '\0' for stringification in the good
	 case.  */
      notation->value = malloc (value_len + 1);
      if (!notation->value)
	{
	  err = gpg_error_from_errno (errno);
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

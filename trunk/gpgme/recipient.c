/* recipient.c - mainatin recipient sets
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

#include "context.h"


/* Create a new uninitialized recipient object and return it in R_RSET.  */
gpgme_error_t
gpgme_recipients_new (gpgme_recipients_t *r_rset)
{
  gpgme_recipients_t rset;
    
  rset = calloc (1, sizeof *rset);
  if (!rset)
    return GPGME_Out_Of_Core;
  *r_rset = rset;
  return 0;
}


/* Release the recipient object RSET.  */
void
gpgme_recipients_release (gpgme_recipients_t rset)
{
  gpgme_user_id_t uid = rset->list;

  while (uid)
    {
      gpgme_user_id_t next_uid = uid->next;

      free (uid);
      uid = next_uid;
    }
  free (rset);
}


/* Add the name NAME to the recipient set RSET with the given key
   validity VALIDITY.  */
gpgme_error_t
gpgme_recipients_add_name_with_validity (gpgme_recipients_t rset,
					 const char *name,
                                         gpgme_validity_t validity)
{
  gpgme_user_id_t uid;

  if (!name || !rset)
    return GPGME_Invalid_Value;
  uid = malloc (sizeof (*uid) + strlen (name) + 1);
  if (!uid)
    return GPGME_Out_Of_Core;
  uid->validity = validity;
  uid->name = "";
  uid->email = "";
  uid->comment = "";
  uid->uid = ((char *) uid) + sizeof (*uid);
  strcpy (uid->uid, name);
  uid->next = rset->list;
  rset->list = uid;
  return 0;
}


/* Add the name NAME to the recipient set RSET.  Same as
   gpgme_recipients_add_name_with_validity with validitiy
   GPGME_VALIDITY_UNKNOWN.  */
gpgme_error_t
gpgme_recipients_add_name (gpgme_recipients_t rset, const char *name)
{
  return gpgme_recipients_add_name_with_validity (rset, name,
						  GPGME_VALIDITY_UNKNOWN);
}


/* Return the number of recipients in the set.  */
unsigned int 
gpgme_recipients_count (const gpgme_recipients_t rset)
{
  gpgme_user_id_t uid = rset->list;
  unsigned int count = 0;
    
  while (uid)
    {
      count++;
      uid = uid->next;
    }

  return count;
}


/* Start an enumeration on the recipient set RSET.  The caller must
   pass the address of a void pointer which is used as the iterator
   object.  */
gpgme_error_t
gpgme_recipients_enum_open (const gpgme_recipients_t rset, void **iter)
{
  *iter = rset->list;
  return 0;
}

/* Return the name of the next recipient in the set RSET.  */
const char *
gpgme_recipients_enum_read (const gpgme_recipients_t rset, void **iter)
{
  gpgme_user_id_t uid;

  uid = *iter;
  if (!uid)
    return NULL;

  *iter = uid->next;
  return uid->name;
}

/* Release the iterator for this object.  */
gpgme_error_t
gpgme_recipients_enum_close (const gpgme_recipients_t rset, void **iter)
{
  /* Not really needed, but might catch the occasional mistake.  */
  *iter = NULL;

  return 0;
}


int
_gpgme_recipients_all_valid (const gpgme_recipients_t rset)
{
  gpgme_user_id_t uid = rset->list;

  while (uid)
    {
      if (uid->validity != GPGME_VALIDITY_FULL
	  && uid->validity != GPGME_VALIDITY_ULTIMATE )
	return 0;
      uid = uid->next;
    }
  return 1;
}

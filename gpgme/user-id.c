/* user-id.c - Managing user IDs.
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

#include <gpgme.h>


/* Release the user IDs in the list UID.  */
void
gpgme_user_ids_release (gpgme_user_id_t uid)
{
  while (uid)
    {
      gpgme_user_id_t next_uid = uid->next;

      free (uid);
      uid = next_uid;
    }
}


/* Add the name NAME to the user ID list *UIDS_P (with unknown
   validity).  */
gpgme_error_t
gpgme_user_ids_append (gpgme_user_id_t *uids_p, const char *name)
{
  gpgme_user_id_t uids;
  gpgme_user_id_t uid;

  if (!name || !uids_p)
    return GPGME_Invalid_Value;

  uid = calloc (1, sizeof (*uid) + strlen (name) + 1);
  if (!uid)
    return GPGME_Out_Of_Core;

  uid->uid = ((char *) uid) + sizeof (*uid);
  strcpy (uid->uid, name);
  uid->name = uid->uid + strlen (name);
  uid->email = uid->name;
  uid->comment = uid->name;
  uid->validity = GPGME_VALIDITY_UNKNOWN;
  
  uids = *uids_p;
  if (uids)
    {
      while (uids->next)
	uids = uids->next;
      uids->next = uid;
    }
  else
    *uids_p = uid;

  return 0;
}


int
_gpgme_user_ids_all_valid (gpgme_user_id_t uid)
{
  while (uid)
    {
      if (uid->validity != GPGME_VALIDITY_FULL
	  && uid->validity != GPGME_VALIDITY_ULTIMATE)
	return 0;
      uid = uid->next;
    }
  return 1;
}

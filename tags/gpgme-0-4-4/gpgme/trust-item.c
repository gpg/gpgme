/* trust-item.c - Trust item objects.
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
#include <assert.h>
#include <errno.h>

#include "util.h"
#include "ops.h"
#include "sema.h"


/* Protects all reference counters in trust items.  All other accesses
   to a trust item are either read only or happen before the trust
   item is available to the user.  */
DEFINE_STATIC_LOCK (trust_item_ref_lock);


/* Create a new trust item.  */
gpgme_error_t
_gpgme_trust_item_new (gpgme_trust_item_t *r_item)
{
  gpgme_trust_item_t item;

  item = calloc (1, sizeof *item);
  if (!item)
    return gpg_error_from_errno (errno);
  item->_refs = 1;
  item->keyid = item->_keyid;
  item->_keyid[16] = '\0';
  item->owner_trust = item->_owner_trust;
  item->_owner_trust[1] = '\0';
  item->validity = item->_validity;
  item->_validity[1] = '\0';
  *r_item = item;
  return 0;
}


/* Acquire a reference to ITEM.  */
void
gpgme_trust_item_ref (gpgme_trust_item_t item)
{
  LOCK (trust_item_ref_lock);
  item->_refs++;
  UNLOCK (trust_item_ref_lock);
}


/* gpgme_trust_item_unref releases the trust item object. Note that
   this function may not do an actual release if there are other
   shallow copies of the object.  You have to call this function for
   every newly created trust item object as well as for every
   gpgme_trust_item_ref() done on the trust item object.  */
void
gpgme_trust_item_unref (gpgme_trust_item_t item)
{
  LOCK (trust_item_ref_lock);
  assert (item->_refs > 0);
  if (--item->_refs)
    {
      UNLOCK (trust_item_ref_lock);
      return;
    }
  UNLOCK (trust_item_ref_lock);

  if (item->name)
    free (item->name);
  free (item);
}


/* Compatibility interfaces.  */
void
gpgme_trust_item_release (gpgme_trust_item_t item)
{
  gpgme_trust_item_unref (item);
}

/* Return the value of the attribute WHAT of ITEM, which has to be
   representable by a string.  */
const char *gpgme_trust_item_get_string_attr (gpgme_trust_item_t item,
					      _gpgme_attr_t what,
					      const void *reserved, int idx)
{
  const char *val = NULL;

  if (!item)
    return NULL;
  if (reserved)
    return NULL;
  if (idx)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      val = item->keyid;
      break;

    case GPGME_ATTR_OTRUST:  
      val = item->owner_trust;
      break;

    case GPGME_ATTR_VALIDITY:
      val = item->validity;
      break;

    case GPGME_ATTR_USERID:  
      val = item->name;
      break;

    default:
      break;
    }
  return val;
}


/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an integer.  IDX specifies a running index if the
   attribute appears more than once in the key.  */
int gpgme_trust_item_get_int_attr (gpgme_trust_item_t item, _gpgme_attr_t what,
				   const void *reserved, int idx)
{
  int val = 0;

  if (!item)
    return 0;
  if (reserved)
    return 0;
  if (idx)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_LEVEL:    
      val = item->level;
      break;

    case GPGME_ATTR_TYPE:    
      val = item->type;
      break;

    default:
      break;
    }
  return val;
}

/* trust-item.c - Trust item objects.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
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
#include <assert.h>
#include <errno.h>

#include "util.h"
#include "ops.h"
#include "sema.h"
#include "debug.h"


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
    return gpg_error_from_syserror ();
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

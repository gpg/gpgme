/* key-cache.c - Key cache routines.
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
#include "ops.h"
#include "sema.h"
#include "key.h"

#if SIZEOF_UNSIGNED_INT < 4
#error unsigned int too short to be used as a hash value
#endif

#define KEY_CACHE_SIZE 503
#define KEY_CACHE_MAX_CHAIN_LENGTH 10

struct key_cache_item_s
{
  struct key_cache_item_s *next;
  GpgmeKey key;
};

/* Protects key_cache and key_cache_unused_items.  */
DEFINE_STATIC_LOCK (key_cache_lock);
static struct key_cache_item_s *key_cache[KEY_CACHE_SIZE];
static struct key_cache_item_s *key_cache_unused_items;


/* We use the first 4 digits to calculate the hash.  */
static int
hash_key (const char *fpr, unsigned int *rhash)
{
  unsigned int hash;
  int c;

  if (!fpr)
    return -1;
  if ((c = _gpgme_hextobyte (fpr)) == -1)
    return -1;
  hash = c;
  if ((c = _gpgme_hextobyte (fpr+2)) == -1)
    return -1;
  hash |= c << 8;
  if ((c = _gpgme_hextobyte (fpr+4)) == -1)
    return -1;
  hash |= c << 16;
  if ((c = _gpgme_hextobyte (fpr+6)) == -1)
    return -1;
  hash |= c << 24;

  *rhash = hash;
  return 0;
}


/* Acquire a reference to KEY and add it to the key cache.  */
void
_gpgme_key_cache_add (GpgmeKey key)
{
  struct subkey_s *k;

  LOCK (key_cache_lock);
  /* Put the key under each fingerprint into the cache.  We use the
     first 4 digits to calculate the hash.  */
  for (k = &key->keys; k; k = k->next)
    {
      size_t n;
      unsigned int hash;
      struct key_cache_item_s *item;

      if (hash_key (k->fingerprint, &hash))
	continue;

      hash %= KEY_CACHE_SIZE;
      for (item = key_cache[hash], n=0; item; item = item->next, n++)
	{
	  struct subkey_s *k2;
	  if (item->key == key) 
	    /* Already in cache.  */
	    break;
	  /* Now do a deeper check.  */
	  for (k2 = &item->key->keys; k2; k2 = k2->next)
	    {
	      if (k2->fingerprint && !strcmp (k->fingerprint, k2->fingerprint))
		{
		  /* Okay, replace it with the new copy.  */
		  gpgme_key_unref (item->key);
		  item->key = key;
		  gpgme_key_ref (item->key);
		  UNLOCK (key_cache_lock);
		  return;
                }
            }
        }
      if (item)
	continue;
        
      if (n > KEY_CACHE_MAX_CHAIN_LENGTH)
	{
	  /* Remove the last entries.  */
	  struct key_cache_item_s *last = NULL;

	  for (item = key_cache[hash];
	       item && n < KEY_CACHE_MAX_CHAIN_LENGTH;
	       last = item, item = item->next, n++)
	    ;
	  
	  if (last)
	    {
	      struct key_cache_item_s *next;

	      last->next = NULL;
	      for (; item; item = next)
		{
		  next = item->next;
		  gpgme_key_unref (item->key);
		  item->key = NULL;
		  item->next = key_cache_unused_items;
		  key_cache_unused_items = item;
                }
            }
        }

      item = key_cache_unused_items;
      if (item)
	{
	  key_cache_unused_items = item->next;
	  item->next = NULL;
        }
      else
	{
	  item = malloc (sizeof *item);
	  if (!item)
	    {
	      UNLOCK (key_cache_lock);
	      return;
	    }
        }

      item->key = key;
      gpgme_key_ref (key);
      item->next = key_cache[hash];
      key_cache[hash] = item;
    }
  UNLOCK (key_cache_lock);
}


GpgmeKey 
_gpgme_key_cache_get (const char *fpr)
{
  struct key_cache_item_s *item;
  unsigned int hash;

  LOCK (key_cache_lock);
  if (hash_key (fpr, &hash))
    {
      UNLOCK (key_cache_lock);
      return NULL;
    }

  hash %= KEY_CACHE_SIZE;
  for (item = key_cache[hash]; item; item = item->next)
    {
      struct subkey_s *k;

      for (k = &item->key->keys; k; k = k->next)
	{
	  if (k->fingerprint && !strcmp (k->fingerprint, fpr))
	    {
	      gpgme_key_ref (item->key);
	      UNLOCK (key_cache_lock);
	      return item->key;
            }
        }
    }
  UNLOCK (key_cache_lock);
  return NULL;
}


/* Get the key with the fingerprint FPR from the key cache or from the
   crypto backend.  If FORCE_UPDATE is true, force a refresh of the
   key from the crypto backend and replace the key in the cache, if
   any.  If SECRET is true, get the secret key.  */
GpgmeError
gpgme_get_key (GpgmeCtx ctx, const char *fpr, GpgmeKey *r_key,
	       int secret, int force_update)
{
  GpgmeCtx listctx;
  GpgmeError err;

  if (!ctx || !r_key)
    return GPGME_Invalid_Value;
  
  if (strlen (fpr) < 16)	/* We have at least a key ID.  */
    return GPGME_Invalid_Key;

  if (!force_update)
    {
      *r_key = _gpgme_key_cache_get (fpr);
      if (*r_key)
	{
	  /* If the primary UID (if available) has no signatures, and
	     we are in the signature listing keylist mode, then try to
	     update the key below before returning.  */
	  if (!((ctx->keylist_mode & GPGME_KEYLIST_MODE_SIGS)
		&& (*r_key)->uids && !(*r_key)->uids->certsigs))
	    return 0;
	}
    }

  /* We need our own context because we have to avoid the user's I/O
     callback handlers.  */
  /* Fixme: This can be optimized by keeping an internal context
     used for such key listings.  */
  err = gpgme_new (&listctx);
  if (err)
    return err;
  gpgme_set_protocol (listctx, gpgme_get_protocol (ctx));
  gpgme_set_keylist_mode (listctx, ctx->keylist_mode);
  err = gpgme_op_keylist_start (listctx, fpr, secret);
  if (!err)
    err = gpgme_op_keylist_next (listctx, r_key);
  gpgme_release (listctx);
  return err;
}

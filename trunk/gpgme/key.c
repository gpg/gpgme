/* key.c - Key objects.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "util.h"
#include "ops.h"
#include "key.h"
#include "sema.h"

#if SIZEOF_UNSIGNED_INT < 4
#error unsigned int too short to be used as a hash value
#endif


struct key_cache_item_s
{
  struct key_cache_item_s *next;
  GpgmeKey key;
};

/* Protects all key_cache_* variables.  */
DEFINE_STATIC_LOCK (key_cache_lock);
static int key_cache_initialized;
static struct key_cache_item_s **key_cache;
static size_t key_cache_size;
static size_t key_cache_max_chain_length;
static struct key_cache_item_s *key_cache_unused_items;

/* Protects all reference counters in keys.  All other accesses to a
   key are either read only or happen before the key is entered into
   the cache.  */
DEFINE_STATIC_LOCK (key_ref_lock);

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


void
_gpgme_key_cache_init (void)
{
  LOCK (key_cache_lock);
  if (!key_cache_initialized)
    {
      key_cache_size = 503;
      key_cache = calloc (key_cache_size, sizeof *key_cache);
      if (!key_cache)
	{
	  key_cache_size = 0;
	  key_cache_initialized = 1;
	}
      else
	{
	  /* The upper bound for our cache size is
	     key_cache_max_chain_length * key_cache_size.  */
	  key_cache_max_chain_length = 10;
	  key_cache_initialized = 1;
	}
    }
  UNLOCK (key_cache_lock);
}


void
_gpgme_key_cache_add (GpgmeKey key)
{
  struct subkey_s *k;

  if (!key)
    return;

  _gpgme_key_cache_init ();

  LOCK (key_cache_lock);
  /* Check if cache was enabled.  */
  if (!key_cache_size)
    {
      UNLOCK (key_cache_lock);
      return;
    }

  /* Put the key under each fingerprint into the cache.  We use the
     first 4 digits to calculate the hash.  */
  for (k = &key->keys; k; k = k->next)
    {
      size_t n;
      unsigned int hash;
      struct key_cache_item_s *item;

      if (hash_key (k->fingerprint, &hash))
	continue;

      hash %= key_cache_size;
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
        
      if (n > key_cache_max_chain_length)
	{
	  /* Remove the last entries.  */
	  struct key_cache_item_s *last = NULL;

	  for (item = key_cache[hash];
	       item && n < key_cache_max_chain_length;
	       last = item, item = item->next, n++)
	    ;
	  
	  if (last)
	    {
	      struct key_cache_item_s *next;

	      assert (last->next == item);
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
  /* Check if cache is enabled already.  */
  if (!key_cache_size)
    {
      UNLOCK (key_cache_lock);
      return NULL;
    }

  if (hash_key (fpr, &hash))
    {
      UNLOCK (key_cache_lock);
      return NULL;
    }

  hash %= key_cache_size;
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


static const char *
pkalgo_to_string (int algo)
{
  switch (algo)
    {
    case 1: 
    case 2:
    case 3:
      return "RSA";

    case 16:
    case 20:
      return "ElG";

    case 17:
      return "DSA";

    default:
      return "Unknown";
    }
}


static const char *
otrust_to_string (int otrust)
{
  switch (otrust)
    {
    case GPGME_VALIDITY_NEVER:
      return "n";

    case GPGME_VALIDITY_MARGINAL:
      return "m";

    case GPGME_VALIDITY_FULL:
      return "f";

    case GPGME_VALIDITY_ULTIMATE:
      return "u";

    default:
      return "?";
    }
}


static const char *
validity_to_string (int validity)
{
  switch (validity)
    {
    case GPGME_VALIDITY_UNDEFINED:
      return "q";

    case GPGME_VALIDITY_NEVER:
      return "n";

    case GPGME_VALIDITY_MARGINAL:
      return "m";

    case GPGME_VALIDITY_FULL:
      return "f";

    case GPGME_VALIDITY_ULTIMATE:
      return "u";

    case GPGME_VALIDITY_UNKNOWN:
    default:
      return "?";
    }
}


static GpgmeError
key_new (GpgmeKey *r_key, int secret)
{
  GpgmeKey key;

  *r_key = NULL;
  key = calloc (1, sizeof *key);
  if (!key)
    return mk_error (Out_Of_Core);
  key->ref_count = 1;
  *r_key = key;
  if (secret)
    key->secret = 1;
  return 0;
}


GpgmeError
_gpgme_key_new (GpgmeKey *r_key)
{
  return key_new (r_key, 0);
}


GpgmeError
_gpgme_key_new_secret (GpgmeKey *r_key)
{
  return key_new (r_key, 1);
}


/**
 * gpgme_key_ref:
 * @key: Key object
 * 
 * To safe memory the Key objects implements reference counting.
 * Use this function to bump the reference counter.
 **/
void
gpgme_key_ref (GpgmeKey key)
{
  return_if_fail (key);
  LOCK (key_ref_lock);
  key->ref_count++;
  UNLOCK (key_ref_lock);
}


static struct subkey_s *
add_subkey (GpgmeKey key, int secret)
{
  struct subkey_s *k, *kk;

  k = calloc (1, sizeof *k);
  if (!k)
    return NULL;

  if (!(kk = key->keys.next))
    key->keys.next = k;
  else
    {
      while (kk->next)
	kk = kk->next;
      kk->next = k;
    }
  if (secret)
    k->secret = 1;
  return k;
}


struct subkey_s *
_gpgme_key_add_subkey (GpgmeKey key)
{
  return add_subkey (key, 0);
}


struct subkey_s *
_gpgme_key_add_secret_subkey (GpgmeKey key)
{
  return add_subkey (key, 1);
}


static char *
set_user_id_part (char *tail, const char *buf, size_t len)
{
  while (len && (buf[len - 1] == ' ' || buf[len - 1] == '\t')) 
    len--;
  for (; len; len--)
    *tail++ = *buf++;
  *tail++ = 0;
  return tail;
}


static void
parse_user_id (const char *src, const char **name, const char **email,
		    const char **comment, char *tail)
{
  const char *start = NULL;
  int in_name = 0;
  int in_email = 0;
  int in_comment = 0;

  while (*src)
    {
      if (in_email)
	{
	  if (*src == '<')
	    /* Not legal but anyway.  */
	    in_email++;
	  else if (*src == '>')
	    {
	      if (!--in_email && !*email)
		{
		  *email = tail;
		  tail = set_user_id_part (tail, start, src - start);
		}
	    }
	}
      else if (in_comment)
	{
	  if (*src == '(')
	    in_comment++;
	  else if (*src == ')')
	    {
	      if (!--in_comment && !*comment)
		{
		  *comment = tail;
		  tail = set_user_id_part (tail, start, src - start);
		}
	    }
	}
      else if (*src == '<')
	{
	  if (in_name)
	    {
	      if (!*name)
		{
		  *name = tail;
		  tail = set_user_id_part (tail, start, src - start);
		}
	      in_name = 0;
	    }
	  in_email = 1;
	  start = src + 1;
	}
      else if (*src == '(')
	{
	  if (in_name)
	    {
	      if (!*name)
		{
		  *name = tail;
		  tail = set_user_id_part (tail, start, src - start);
		}
	      in_name = 0;
	    }
	  in_comment = 1;
	  start = src + 1;
	}
      else if (!in_name && *src != ' ' && *src != '\t')
	{
	  in_name = 1;
	  start = src;
	}    
      src++;
    }
 
  if (in_name)
    {
      if (!*name)
	{
	  *name = tail;
	  tail = set_user_id_part (tail, start, src - start);
	}
    }
 
  /* Let unused parts point to an EOS.  */
  tail--;
  if (!*name)
    *name = tail;
  if (!*email)
    *email = tail;
  if (!*comment)
    *comment = tail;
}


static void
parse_x509_user_id (const char *src, const char **name, const char **email,
		    const char **comment, char *tail)
{
  if (*src == '<' && src[strlen (src) - 1] == '>')
    *email = src;
  
  /* Let unused parts point to an EOS.  */
  tail--;
  if (!*name)
    *name = tail;
  if (!*email)
    *email = tail;
  if (!*comment)
    *comment = tail;
}


struct certsig_s *
_gpgme_key_add_certsig (GpgmeKey key, char *src)
{
  int src_len = src ? strlen (src) : 0;
  struct user_id_s *uid;
  struct certsig_s *certsig;

  assert (key);	/* XXX */

  uid = key->last_uid;
  assert (uid);	/* XXX */

  /* We can malloc a buffer of the same length, because the converted
     string will never be larger. Actually we allocate it twice the
     size, so that we are able to store the parsed stuff there too.  */
  certsig = calloc (1, sizeof (*certsig) + 2 * src_len + 3);
  if (!certsig)
    return NULL;

  if (src)
    {
      char *dst = certsig->name;
      _gpgme_decode_c_string (src, &dst, src_len + 1);
      dst += src_len + 1;
      if (key->x509)
	parse_x509_user_id (src, &certsig->name_part, &certsig->email_part,
			    &certsig->comment_part, dst);
      else
	parse_user_id (src, &certsig->name_part, &certsig->email_part,
		       &certsig->comment_part, dst);
    }

  if (!uid->certsigs)
    uid->certsigs = certsig;
  if (uid->last_certsig)
    uid->last_certsig->next = certsig;
  uid->last_certsig = certsig;

  return certsig;
}


/**
 * gpgme_key_release:
 * @key: Key Object or NULL
 * 
 * Release the key object. Note, that this function may not do an
 * actual release if there are other shallow copies of the objects.
 * You have to call this function for every newly created key object
 * as well as for every gpgme_key_ref() done on the key object.
 **/
void
gpgme_key_release (GpgmeKey key)
{
  struct certsig_s *c, *c2;
  struct user_id_s *u, *u2;
  struct subkey_s *k, *k2;

  if (!key)
    return;

  LOCK (key_ref_lock);
  assert (key->ref_count);
  if (--key->ref_count)
    {
      UNLOCK (key_ref_lock);
      return;
    }
  UNLOCK (key_ref_lock);

  free (key->keys.fingerprint);
  for (k = key->keys.next; k; k = k2)
    {
      k2 = k->next;
      free (k->fingerprint);
      free (k);
    }
  for (u = key->uids; u; u = u2)
    {
      u2 = u->next;
      for (c = u->certsigs; c; c = c2)
        {
          c2 = c->next;
          free (c);
        }
      free (u);
    }
  free (key->issuer_serial);
  free (key->issuer_name);
  free (key->chain_id);
  free (key);
}


/**
 * gpgme_key_unref:
 * @key: Key Object
 * 
 * This is an alias for gpgme_key_release().
 **/
void
gpgme_key_unref (GpgmeKey key)
{
  gpgme_key_release (key);
}


/* Take a name from the --with-colon listing, remove certain escape
   sequences sequences and put it into the list of UIDs.  */
GpgmeError
_gpgme_key_append_name (GpgmeKey key, const char *src)
{
  struct user_id_s *uid;
  char *dst;
  int src_len = strlen (src);

  assert (key);
  /* We can malloc a buffer of the same length, because the converted
     string will never be larger. Actually we allocate it twice the
     size, so that we are able to store the parsed stuff there too.  */
  uid = malloc (sizeof (*uid) + 2 * src_len + 3);
  if (!uid)
    return mk_error (Out_Of_Core);
  memset (uid, 0, sizeof *uid);

  dst = uid->name;
  _gpgme_decode_c_string (src, &dst, src_len + 1);

  dst += src_len + 1;
  if (key->x509)
    parse_x509_user_id (src, &uid->name_part, &uid->email_part,
			&uid->comment_part, dst);
  else
    parse_user_id (src, &uid->name_part, &uid->email_part,
		   &uid->comment_part, dst);

  if (!key->uids)
    key->uids = uid;
  if (key->last_uid)
    key->last_uid->next = uid;
  key->last_uid = uid;

  return 0;
}


static void
add_otag (GpgmeData d, const char *tag)
{
  _gpgme_data_append_string (d, "    <");
  _gpgme_data_append_string (d, tag);
  _gpgme_data_append_string (d, ">");
}


static void
add_ctag (GpgmeData d, const char *tag)
{
  _gpgme_data_append_string (d, "</");
  _gpgme_data_append_string (d, tag);
  _gpgme_data_append_string (d, ">\n");
}


static void
add_tag_and_string (GpgmeData d, const char *tag, const char *string)
{
  add_otag (d, tag);
  _gpgme_data_append_string_for_xml (d, string);
  add_ctag (d, tag); 
}


static void
add_tag_and_uint (GpgmeData d, const char *tag, unsigned int val)
{
  char buf[30];
  sprintf (buf, "%u", val);
  add_tag_and_string (d, tag, buf);
}


static void
add_tag_and_time (GpgmeData d, const char *tag, time_t val)
{
  char buf[30];

  if (!val || val == (time_t) - 1)
    return;
  sprintf (buf, "%lu", (unsigned long) val);
  add_tag_and_string (d, tag, buf);
}


static void
one_certsig_as_xml (GpgmeData data, struct certsig_s *certsig)
{
  _gpgme_data_append_string (data, "    <signature>\n");
  if (certsig->flags.invalid)
    _gpgme_data_append_string (data, "      <invalid/>\n");
  if (certsig->flags.revoked)
    _gpgme_data_append_string (data, "      <revoked/>\n");
  if (certsig->flags.expired)
    _gpgme_data_append_string (data, "      <expired/>\n");
  add_tag_and_string (data, "keyid", certsig->keyid);
  add_tag_and_uint (data, "algo", certsig->algo);
  add_tag_and_time (data, "created", certsig->timestamp);
  add_tag_and_time (data, "expire", certsig->expires_at);
  if (*certsig->name)
    add_tag_and_string (data, "raw", certsig->name);
  if (*certsig->name_part)
    add_tag_and_string (data, "name", certsig->name_part);
  if (*certsig->email_part)
    add_tag_and_string (data, "email", certsig->email_part);
  if (*certsig->comment_part)
    add_tag_and_string (data, "comment", certsig->comment_part);
  _gpgme_data_append_string (data, "    </signature>\n");
}


static void
one_uid_as_xml (GpgmeData data, struct user_id_s *uid)
{
  struct certsig_s *certsig;

  _gpgme_data_append_string (data, "  <userid>\n");
  if (uid->invalid)
    _gpgme_data_append_string (data, "    <invalid/>\n");
  if (uid->revoked)
    _gpgme_data_append_string (data, "    <revoked/>\n");
  add_tag_and_string (data, "raw", uid->name);
  if (*uid->name_part)
    add_tag_and_string (data, "name", uid->name_part);
  if (*uid->email_part)
    add_tag_and_string (data, "email", uid->email_part);
  if (*uid->comment_part)
    add_tag_and_string (data, "comment", uid->comment_part);

  /* Now the signatures.  */
  for (certsig = uid->certsigs; certsig; certsig = certsig->next)
    one_certsig_as_xml (data, certsig);
  _gpgme_data_append_string (data, "  </userid>\n");
}


/**
 * gpgme_key_get_as_xml:
 * @key: Key object
 * 
 * Return the key object as an XML string.  The classer has to free
 * that string.
 * 
 * Return value:  An XML string or NULL in case of a memory problem or
 *                a NULL passed as @key
 **/
char *
gpgme_key_get_as_xml (GpgmeKey key)
{
  GpgmeData d;
  struct user_id_s *u;
  struct subkey_s *k;
  
  if (!key)
    return NULL;
  
  if (gpgme_data_new (&d))
    return NULL;
  
  _gpgme_data_append_string (d, "<GnupgKeyblock>\n"
			     "  <mainkey>\n");
  if (key->keys.secret)
    _gpgme_data_append_string (d, "    <secret/>\n");
  if (key->keys.flags.invalid)
    _gpgme_data_append_string (d, "    <invalid/>\n");
  if (key->keys.flags.revoked)
    _gpgme_data_append_string (d, "    <revoked/>\n");
  if (key->keys.flags.expired)
    _gpgme_data_append_string (d, "    <expired/>\n");
  if (key->keys.flags.disabled)
    _gpgme_data_append_string (d, "    <disabled/>\n");
  add_tag_and_string (d, "keyid", key->keys.keyid);
  if (key->keys.fingerprint)
    add_tag_and_string (d, "fpr", key->keys.fingerprint);
  add_tag_and_uint (d, "algo", key->keys.key_algo);
  add_tag_and_uint (d, "len", key->keys.key_len);
  add_tag_and_time (d, "created", key->keys.timestamp);
  add_tag_and_time (d, "expire", key->keys.expires_at);
  add_tag_and_string (d, "otrust", otrust_to_string (key->otrust));
  if (key->issuer_serial)
    add_tag_and_string (d, "serial", key->issuer_serial);
  if (key->issuer_name)
    add_tag_and_string (d, "issuer", key->issuer_name);
  if (key->chain_id)
    add_tag_and_string (d, "chainid", key->chain_id);
  _gpgme_data_append_string (d, "  </mainkey>\n");

  /* Now the user IDs.  */
  for (u = key->uids; u; u = u->next)
    one_uid_as_xml (d,u);
  
  /* And now the subkeys.  */
  for (k = key->keys.next; k; k = k->next)
    {
      _gpgme_data_append_string (d, "  <subkey>\n");
      if (k->secret)
        _gpgme_data_append_string (d, "    <secret/>\n");
      if (k->flags.invalid)
        _gpgme_data_append_string (d, "    <invalid/>\n");
      if (k->flags.revoked)
        _gpgme_data_append_string (d, "    <revoked/>\n");
      if (k->flags.expired)
        _gpgme_data_append_string (d, "    <expired/>\n");
      if (k->flags.disabled)
        _gpgme_data_append_string (d, "    <disabled/>\n");
      add_tag_and_string (d, "keyid", k->keyid);
      if (k->fingerprint)
        add_tag_and_string (d, "fpr", k->fingerprint);
      add_tag_and_uint (d, "algo", k->key_algo);
      add_tag_and_uint (d, "len", k->key_len);
      add_tag_and_time (d, "created", k->timestamp);
      add_tag_and_time (d, "expire", k->expires_at);
      _gpgme_data_append_string (d, "  </subkey>\n");
    }
  _gpgme_data_append_string (d, "</GnupgKeyblock>\n");
  
  return _gpgme_data_release_and_return_string (d);
}


static const char *
capabilities_to_string (struct subkey_s *k)
{
  static const char *const strings[8] =
    {
      "",
      "c",
      "s",
      "sc",
      "e",
      "ec",
      "es",
      "esc"
    };
  return strings[(!!k->flags.can_encrypt << 2)
		 | (!!k->flags.can_sign << 1)
		 | (!!k->flags.can_certify)];
}


/**
 * gpgme_key_get_string_attr:
 * @key: Key Object
 * @what: Attribute specifier
 * @reserved: Must be 0
 * @idx: Index counter
 * 
 * Return a attribute as specified by @what and @idx.  Note that not
 * all attributes can be returned as a string, in which case NULL is
 * returned.  @idx is used to iterate through attributes which do have
 * more than one instance (e.g. user IDs or sub keys).
 * 
 * Return value: NULL or an const string which is only valid as long
 * as the key object itself is valid.
 **/
const char *
gpgme_key_get_string_attr (GpgmeKey key, GpgmeAttr what,
			   const void *reserved, int idx)
{
  struct subkey_s *subkey;
  struct user_id_s *uid;
  int i;

  if (!key || reserved || idx < 0)
    return NULL;

  /* Select IDXth subkey.  */
  subkey = &key->keys;
  for (i = 0; i < idx; i++)
    {
      subkey = subkey->next;
      if (!subkey)
	break;
    }

  /* Select the IDXth user ID.  */
  uid = key->uids;
  for (i = 0; i < idx; i++)
    {
      uid = uid->next;
      if (!uid)
	break;
    }

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      return subkey ? subkey->keyid : NULL;

    case GPGME_ATTR_FPR:
      return subkey ? subkey->fingerprint : NULL;

    case GPGME_ATTR_ALGO:    
      return subkey ? pkalgo_to_string (subkey->key_algo) : NULL;

    case GPGME_ATTR_TYPE:
      return key->x509 ? "X.509" : "PGP";

    case GPGME_ATTR_OTRUST:
      return otrust_to_string (key->otrust);

    case GPGME_ATTR_USERID:  
      return uid ? uid->name : NULL;

    case GPGME_ATTR_NAME:   
      return uid ? uid->name_part : NULL;

    case GPGME_ATTR_EMAIL:
      return uid ? uid->email_part : NULL;

    case GPGME_ATTR_COMMENT:
      return uid ? uid->comment_part : NULL;

    case GPGME_ATTR_VALIDITY:
      return otrust_to_string (key->otrust);

    case GPGME_ATTR_KEY_CAPS:    
      return subkey ? capabilities_to_string (subkey) : NULL;

    case GPGME_ATTR_SERIAL:
      return key->issuer_serial;

    case GPGME_ATTR_ISSUER:
      return idx ? NULL : key->issuer_name;

    case GPGME_ATTR_CHAINID:
      return  key->chain_id;

    default:
      return NULL;
    }
}


/**
 * gpgme_key_get_ulong_attr:
 * @key: 
 * @what: 
 * @reserved: 
 * @idx: 
 * 
 * Return a attribute as specified by @what and @idx.  Note that not
 * all attributes can be returned as an integer, in which case 0 is
 * returned.  @idx is used to iterate through attributes which do have
 * more than one instance (e.g. user IDs or sub keys).
 *
 * See gpgme.h for a list of attributes.
 * 
 * Return value: 0 or the requested value.
 **/
unsigned long
gpgme_key_get_ulong_attr (GpgmeKey key, GpgmeAttr what,
			  const void *reserved, int idx)
{
  struct subkey_s *subkey;
  struct user_id_s *uid;
  int i;

  if (!key || reserved || idx < 0)
    return 0;

  /* Select IDXth subkey.  */
  subkey = &key->keys;
  for (i = 0; i < idx; i++)
    {
      subkey = subkey->next;
      if (!subkey)
	break;
    }

  /* Select the IDXth user ID.  */
  uid = key->uids;
  for (i = 0; i < idx; i++)
    {
      uid = uid->next;
      if (!uid)
	break;
    }

  switch (what)
    {
    case GPGME_ATTR_ALGO:
      return subkey ? (unsigned long) subkey->key_algo : 0;

    case GPGME_ATTR_LEN:
      return subkey ? (unsigned long) subkey->key_len : 0;

    case GPGME_ATTR_TYPE:
      return key->x509 ? 1 : 0;

    case GPGME_ATTR_CREATED: 
      return (subkey && subkey->timestamp >= 0)
	? (unsigned long) subkey->timestamp : 0;

    case GPGME_ATTR_EXPIRE: 
      return (subkey && subkey->expires_at >= 0)
	? (unsigned long) subkey->expires_at : 0;

    case GPGME_ATTR_VALIDITY:
      return uid ? uid->validity : 0;

    case GPGME_ATTR_OTRUST:
      return key->otrust;

    case GPGME_ATTR_IS_SECRET:
      return !!key->secret;

    case GPGME_ATTR_KEY_REVOKED:
      return subkey ? subkey->flags.revoked : 0;

    case GPGME_ATTR_KEY_INVALID:
      return subkey ? subkey->flags.invalid : 0;

    case GPGME_ATTR_KEY_EXPIRED:
      return subkey ? subkey->flags.expired : 0;

    case GPGME_ATTR_KEY_DISABLED:
      return subkey ? subkey->flags.disabled : 0;

    case GPGME_ATTR_UID_REVOKED:
      return uid ? uid->revoked : 0;

    case GPGME_ATTR_UID_INVALID:
      return uid ? uid->invalid : 0;

    case GPGME_ATTR_CAN_ENCRYPT:
      return key->gloflags.can_encrypt;

    case GPGME_ATTR_CAN_SIGN:
      return key->gloflags.can_sign;

    case GPGME_ATTR_CAN_CERTIFY:
      return key->gloflags.can_certify;

    default:
      return 0;
    }
}


static struct certsig_s *
get_certsig (GpgmeKey key, int uid_idx, int idx)
{
  struct user_id_s *uid;
  struct certsig_s *certsig;

  if (!key || uid_idx < 0 || idx < 0)
    return NULL;

  uid = key->uids;
  while (uid && uid_idx > 0)
    {
      uid = uid->next;
      uid_idx--;
    }
  if (!uid)
    return NULL;

  certsig = uid->certsigs;
  while (certsig && idx > 0)
    {
      certsig = certsig->next;
      idx--;
    }
  return certsig;
}


const char *
gpgme_key_sig_get_string_attr (GpgmeKey key, int uid_idx, GpgmeAttr what,
			       const void *reserved, int idx)
{
  struct certsig_s *certsig = get_certsig (key, uid_idx, idx);

  if (!certsig || reserved)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      return certsig->keyid;

    case GPGME_ATTR_ALGO:    
      return pkalgo_to_string (certsig->algo);

    case GPGME_ATTR_USERID:  
      return certsig->name;

    case GPGME_ATTR_NAME:   
      return certsig->name_part;

    case GPGME_ATTR_EMAIL:
      return certsig->email_part;

    case GPGME_ATTR_COMMENT:
      return certsig->comment_part;
   
    default:
      return NULL;
    }
}


unsigned long
gpgme_key_sig_get_ulong_attr (GpgmeKey key, int uid_idx, GpgmeAttr what,
			      const void *reserved, int idx)
{
  struct certsig_s *certsig = get_certsig (key, uid_idx, idx);

  if (!certsig || reserved)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_ALGO:    
      return (unsigned long) certsig->algo;

    case GPGME_ATTR_CREATED: 
      return certsig->timestamp < 0 ? 0L : (unsigned long) certsig->timestamp;

    case GPGME_ATTR_EXPIRE: 
      return certsig->expires_at < 0 ? 0L : (unsigned long) certsig->expires_at;

    case GPGME_ATTR_KEY_REVOKED:
      return certsig->flags.revoked;

    case GPGME_ATTR_KEY_INVALID:
      return certsig->flags.invalid;

    case GPGME_ATTR_KEY_EXPIRED:
      return certsig->flags.expired;

    case GPGME_ATTR_SIG_CLASS:
      return certsig->sig_class;

    case GPGME_ATTR_SIG_STATUS:
      return certsig->sig_stat;

    default:
      return 0;
    }
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
    return mk_error (Invalid_Value);
  if (ctx->pending)
    return mk_error (Busy);
  
  if (strlen (fpr) < 16)	/* We have at least a key ID.  */
    return mk_error (Invalid_Key);

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

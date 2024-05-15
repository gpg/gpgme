/* key.c - Key objects.
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
#include "mbox-util.h"



/* Protects all reference counters in keys.  All other accesses to a
   key are read only.  */
DEFINE_STATIC_LOCK (key_ref_lock);


/* Create a new key.  */
gpgme_error_t
_gpgme_key_new (gpgme_key_t *r_key)
{
  gpgme_key_t key;

  key = calloc (1, sizeof *key);
  if (!key)
    return gpg_error_from_syserror ();
  key->_refs = 1;

  *r_key = key;
  return 0;
}


gpgme_error_t
_gpgme_key_add_subkey (gpgme_key_t key, gpgme_subkey_t *r_subkey)
{
  gpgme_subkey_t subkey;

  subkey = calloc (1, sizeof *subkey);
  if (!subkey)
    return gpg_error_from_syserror ();
  subkey->keyid = subkey->_keyid;
  subkey->_keyid[16] = '\0';

  if (!key->subkeys)
    key->subkeys = subkey;
  if (key->_last_subkey)
    key->_last_subkey->next = subkey;
  key->_last_subkey = subkey;

  *r_subkey = subkey;
  return 0;
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
parse_user_id (char *src, char **name, char **email,
	       char **comment, char *tail)
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
parse_x509_user_id (char *src, char **name, char **email,
		    char **comment, char *tail)
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


/* Take a name from the --with-colon listing, remove certain escape
   sequences sequences and put it into the list of UIDs.  */
gpgme_error_t
_gpgme_key_append_name (gpgme_key_t key, const char *src, int convert)
{
  gpgme_user_id_t uid;
  char *dst;
  int src_len = strlen (src);

  assert (key);
  /* We can malloc a buffer of the same length, because the converted
     string will never be larger. Actually we allocate it twice the
     size, so that we are able to store the parsed stuff there too.  */
  uid = malloc (sizeof (*uid) + 2 * src_len + 3);
  if (!uid)
    return gpg_error_from_syserror ();
  memset (uid, 0, sizeof *uid);

  uid->uid = ((char *) uid) + sizeof (*uid);
  dst = uid->uid;
  if (convert)
    _gpgme_decode_c_string (src, &dst, src_len + 1);
  else
    memcpy (dst, src, src_len + 1);

  dst += strlen (dst) + 1;
  if (key->protocol == GPGME_PROTOCOL_CMS)
    parse_x509_user_id (uid->uid, &uid->name, &uid->email,
			&uid->comment, dst);
  else
    parse_user_id (uid->uid, &uid->name, &uid->email,
		   &uid->comment, dst);

  uid->address = _gpgme_mailbox_from_userid (uid->uid);
  if ((!uid->email || !*uid->email) && uid->address && uid->name
      && !strcmp (uid->name, uid->address))
    {
      /* Name and address are the same. This is a mailbox only key.
         Use address as email and remove name. */
      *uid->name = '\0';
      uid->email = uid->address;
    }

  if (!key->uids)
    key->uids = uid;
  if (key->_last_uid)
    key->_last_uid->next = uid;
  key->_last_uid = uid;

  return 0;
}


gpgme_key_sig_t
_gpgme_key_add_sig (gpgme_key_t key, char *src)
{
  int src_len = src ? strlen (src) : 0;
  gpgme_user_id_t uid;
  gpgme_key_sig_t sig;

  assert (key);	/* XXX */

  uid = key->_last_uid;
  assert (uid);	/* XXX */

  /* We can malloc a buffer of the same length, because the converted
     string will never be larger.  Actually we allocate it twice the
     size, so that we are able to store the parsed stuff there too.  */
  sig = malloc (sizeof (*sig) + 2 * src_len + 3);
  if (!sig)
    return NULL;
  memset (sig, 0, sizeof *sig);

  sig->keyid = sig->_keyid;
  sig->_keyid[16] = '\0';
  sig->uid = ((char *) sig) + sizeof (*sig);

  if (src)
    {
      char *dst = sig->uid;
      _gpgme_decode_c_string (src, &dst, src_len + 1);
      dst += strlen (dst) + 1;
      if (key->protocol == GPGME_PROTOCOL_CMS)
	parse_x509_user_id (sig->uid, &sig->name, &sig->email,
			    &sig->comment, dst);
      else
	parse_user_id (sig->uid, &sig->name, &sig->email,
		       &sig->comment, dst);
    }
  else
    sig->uid[0] = '\0';

  if (!uid->signatures)
    uid->signatures = sig;
  if (uid->_last_keysig)
    uid->_last_keysig->next = sig;
  uid->_last_keysig = sig;

  return sig;
}


gpgme_error_t
_gpgme_key_add_rev_key (gpgme_key_t key, const char *src)
{
  gpgme_revocation_key_t revkey;
  int src_len = src ? strlen (src) : 0;

  assert (key);
  /* malloc a buffer for the revocation key and the fingerprint.  */
  revkey = malloc (sizeof (*revkey) + src_len + 1);
  if (!revkey)
    return gpg_error_from_syserror ();
  memset (revkey, 0, sizeof *revkey);

  revkey->fpr = ((char *) revkey) + sizeof (*revkey);
  if (src)
    memcpy (revkey->fpr, src, src_len + 1);
  else
    revkey->fpr[0] = '\0';

  if (!key->revocation_keys)
    key->revocation_keys = revkey;
  if (key->_last_revkey)
    key->_last_revkey->next = revkey;
  key->_last_revkey = revkey;

  return 0;
}


/* Acquire a reference to KEY.  */
void
gpgme_key_ref (gpgme_key_t key)
{
  LOCK (key_ref_lock);
  key->_refs++;
  UNLOCK (key_ref_lock);
}


/* gpgme_key_unref releases the key object.  Note, that this function
   may not do an actual release if there are other shallow copies of
   the objects.  You have to call this function for every newly
   created key object as well as for every gpgme_key_ref() done on the
   key object.  */
void
gpgme_key_unref (gpgme_key_t key)
{
  gpgme_user_id_t uid;
  gpgme_subkey_t subkey;
  gpgme_revocation_key_t revkey;

  if (!key)
    return;

  LOCK (key_ref_lock);
  assert (key->_refs > 0);
  if (--key->_refs)
    {
      UNLOCK (key_ref_lock);
      return;
    }
  UNLOCK (key_ref_lock);

  subkey = key->subkeys;
  while (subkey)
    {
      gpgme_subkey_t next = subkey->next;
      free (subkey->fpr);
      free (subkey->v5fpr);
      free (subkey->curve);
      free (subkey->keygrip);
      free (subkey->card_number);
      free (subkey);
      subkey = next;
    }

  uid = key->uids;
  while (uid)
    {
      gpgme_user_id_t next_uid = uid->next;
      gpgme_key_sig_t keysig = uid->signatures;
      gpgme_tofu_info_t tofu = uid->tofu;

      while (keysig)
	{
	  gpgme_key_sig_t next_keysig = keysig->next;
	  gpgme_sig_notation_t notation = keysig->notations;

	  while (notation)
	    {
	      gpgme_sig_notation_t next_notation = notation->next;

	      _gpgme_sig_notation_free (notation);
	      notation = next_notation;
	    }

	  free (keysig->trust_scope);
          free (keysig);
	  keysig = next_keysig;
        }

      while (tofu)
        {
          /* NB: The ->next is currently not used but we are prepared
           * for it.  */
          gpgme_tofu_info_t tofu_next = tofu->next;

          free (tofu->description);
          free (tofu);
          tofu = tofu_next;
        }

      free (uid->address);
      free (uid->uidhash);
      free (uid);
      uid = next_uid;
    }

  revkey = key->revocation_keys;
  while (revkey)
    {
      gpgme_revocation_key_t next = revkey->next;
      free (revkey);
      revkey = next;
    }

  free (key->issuer_serial);
  free (key->issuer_name);
  free (key->chain_id);
  free (key->fpr);

  free (key);
}



/* Support functions.  */

/* Create a dummy key to specify an email address.  */
gpgme_error_t
gpgme_key_from_uid (gpgme_key_t *r_key, const char *name)
{
  gpgme_error_t err;
  gpgme_key_t key;

  *r_key = NULL;
  err = _gpgme_key_new (&key);
  if (err)
    return err;

  /* Note: protocol doesn't matter if only email is provided.  */
  err = _gpgme_key_append_name (key, name, 0);
  if (err)
    gpgme_key_unref (key);
  else
    *r_key = key;

  return err;
}



/* Compatibility interfaces.  */

void
gpgme_key_release (gpgme_key_t key)
{
  gpgme_key_unref (key);
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


static const char *
capabilities_to_string (gpgme_subkey_t subkey)
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
  return strings[(!!subkey->can_encrypt << 2)
		 | (!!subkey->can_sign << 1)
		 | (!!subkey->can_certify)];
}


/* Return the value of the attribute WHAT of ITEM, which has to be
   representable by a string.  */
const char *
gpgme_key_get_string_attr (gpgme_key_t key, _gpgme_attr_t what,
			   const void *reserved, int idx)
{
  gpgme_subkey_t subkey;
  gpgme_user_id_t uid;
  int i;

  if (!key || reserved || idx < 0)
    return NULL;

  /* Select IDXth subkey.  */
  subkey = key->subkeys;
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
      return subkey ? subkey->fpr : NULL;

    case GPGME_ATTR_ALGO:
      return subkey ? gpgme_pubkey_algo_name (subkey->pubkey_algo) : NULL;

    case GPGME_ATTR_TYPE:
      return key->protocol == GPGME_PROTOCOL_CMS ? "X.509" : "PGP";

    case GPGME_ATTR_OTRUST:
      return otrust_to_string (key->owner_trust);

    case GPGME_ATTR_USERID:
      return uid ? uid->uid : NULL;

    case GPGME_ATTR_NAME:
      return uid ? uid->name : NULL;

    case GPGME_ATTR_EMAIL:
      return uid ? uid->email : NULL;

    case GPGME_ATTR_COMMENT:
      return uid ? uid->comment : NULL;

    case GPGME_ATTR_VALIDITY:
      return uid ? validity_to_string (uid->validity) : NULL;

    case GPGME_ATTR_KEY_CAPS:
      return subkey ? capabilities_to_string (subkey) : NULL;

    case GPGME_ATTR_SERIAL:
      return key->issuer_serial;

    case GPGME_ATTR_ISSUER:
      return idx ? NULL : key->issuer_name;

    case GPGME_ATTR_CHAINID:
      return key->chain_id;

    default:
      return NULL;
    }
}


unsigned long
gpgme_key_get_ulong_attr (gpgme_key_t key, _gpgme_attr_t what,
			  const void *reserved, int idx)
{
  gpgme_subkey_t subkey;
  gpgme_user_id_t uid;
  int i;

  if (!key || reserved || idx < 0)
    return 0;

  /* Select IDXth subkey.  */
  subkey = key->subkeys;
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
      return subkey ? (unsigned long) subkey->pubkey_algo : 0;

    case GPGME_ATTR_LEN:
      return subkey ? (unsigned long) subkey->length : 0;

    case GPGME_ATTR_TYPE:
      return key->protocol == GPGME_PROTOCOL_CMS ? 1 : 0;

    case GPGME_ATTR_CREATED:
      return (subkey && subkey->timestamp >= 0)
	? (unsigned long) subkey->timestamp : 0;

    case GPGME_ATTR_EXPIRE:
      return (subkey && subkey->expires >= 0)
	? (unsigned long) subkey->expires : 0;

    case GPGME_ATTR_VALIDITY:
      return uid ? uid->validity : 0;

    case GPGME_ATTR_OTRUST:
      return key->owner_trust;

    case GPGME_ATTR_IS_SECRET:
      return !!key->secret;

    case GPGME_ATTR_KEY_REVOKED:
      return subkey ? subkey->revoked : 0;

    case GPGME_ATTR_KEY_INVALID:
      return subkey ? subkey->invalid : 0;

    case GPGME_ATTR_KEY_EXPIRED:
      return subkey ? subkey->expired : 0;

    case GPGME_ATTR_KEY_DISABLED:
      return subkey ? subkey->disabled : 0;

    case GPGME_ATTR_UID_REVOKED:
      return uid ? uid->revoked : 0;

    case GPGME_ATTR_UID_INVALID:
      return uid ? uid->invalid : 0;

    case GPGME_ATTR_CAN_ENCRYPT:
      return key->can_encrypt;

    case GPGME_ATTR_CAN_SIGN:
      return key->can_sign;

    case GPGME_ATTR_CAN_CERTIFY:
      return key->can_certify;

    default:
      return 0;
    }
}


static gpgme_key_sig_t
get_keysig (gpgme_key_t key, int uid_idx, int idx)
{
  gpgme_user_id_t uid;
  gpgme_key_sig_t sig;

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

  sig = uid->signatures;
  while (sig && idx > 0)
    {
      sig = sig->next;
      idx--;
    }
  return sig;
}


const char *
gpgme_key_sig_get_string_attr (gpgme_key_t key, int uid_idx,
			       _gpgme_attr_t what,
			       const void *reserved, int idx)
{
  gpgme_key_sig_t certsig = get_keysig (key, uid_idx, idx);

  if (!certsig || reserved)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_KEYID:
      return certsig->keyid;

    case GPGME_ATTR_ALGO:
      return gpgme_pubkey_algo_name (certsig->pubkey_algo);

    case GPGME_ATTR_USERID:
      return certsig->uid;

    case GPGME_ATTR_NAME:
      return certsig->name;

    case GPGME_ATTR_EMAIL:
      return certsig->email;

    case GPGME_ATTR_COMMENT:
      return certsig->comment;

    default:
      return NULL;
    }
}


unsigned long
gpgme_key_sig_get_ulong_attr (gpgme_key_t key, int uid_idx, _gpgme_attr_t what,
			      const void *reserved, int idx)
{
  gpgme_key_sig_t certsig = get_keysig (key, uid_idx, idx);

  if (!certsig || reserved)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_ALGO:
      return (unsigned long) certsig->pubkey_algo;

    case GPGME_ATTR_CREATED:
      return certsig->timestamp < 0 ? 0L : (unsigned long) certsig->timestamp;

    case GPGME_ATTR_EXPIRE:
      return certsig->expires < 0 ? 0L : (unsigned long) certsig->expires;

    case GPGME_ATTR_KEY_REVOKED:
      return certsig->revoked;

    case GPGME_ATTR_KEY_INVALID:
      return certsig->invalid;

    case GPGME_ATTR_KEY_EXPIRED:
      return certsig->expired;

    case GPGME_ATTR_SIG_CLASS:
      return certsig->sig_class;

    case GPGME_ATTR_SIG_STATUS:
      return certsig->status;

    default:
      return 0;
    }
}

/* keylist.c - Listing keys.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "key.h"
#include "debug.h"


struct keylist_result
{
  int truncated;
  GpgmeData xmlinfo;
};
typedef struct keylist_result *KeylistResult;

static void
release_keylist_result (void *hook)
{
  KeylistResult result = (KeylistResult) hook;

  if (result->xmlinfo)
    gpgme_data_release (result->xmlinfo);
}


/* Append some XML info.  args is currently ignore but we might want
   to add more information in the future (like source of the
   keylisting.  With args of NULL the XML structure is closed.  */
static void
append_xml_keylistinfo (GpgmeData *rdh, char *args)
{
  GpgmeData dh;

  if (!*rdh)
    {
      if (gpgme_data_new (rdh))
	return; /* FIXME: We are ignoring out-of-core.  */
      dh = *rdh;
      _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
  else
    {
      dh = *rdh;
      _gpgme_data_append_string (dh, "  </keylisting>\n");
    }

  if (!args)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
      return;
    }

  _gpgme_data_append_string (dh, "  <keylisting>\n    <truncated/>\n");
    
}


static GpgmeError
keylist_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GpgmeError err;
  KeylistResult result;

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, (void **) &result,
			       sizeof (*result), release_keylist_result);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_TRUNCATED:
      result->truncated = 1;
      break;

    case GPGME_STATUS_EOF:
      if (result->truncated)
        append_xml_keylistinfo (&result->xmlinfo, "1");
      if (result->xmlinfo)
	{
	  append_xml_keylistinfo (&result->xmlinfo, NULL);
	  _gpgme_set_op_info (ctx, result->xmlinfo);
	  result->xmlinfo = NULL;
        }
      break;

    default:
      break;
    }
  return 0;
}


static time_t
parse_timestamp (char *timestamp)
{
  if (!*timestamp)
    return 0;

  return (time_t) strtoul (timestamp, NULL, 10);
}


static void
set_mainkey_trust_info (GpgmeKey key, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'e':
	  key->keys.flags.expired = 1;
	  break;

	case 'r':
	  key->keys.flags.revoked = 1;
	  break;

	case 'd':
          /* Note that gpg 1.3 won't print that anymore but only uses
             the capabilities field. */
	  key->keys.flags.disabled = 1;
	  break;

	case 'i':
	  key->keys.flags.invalid = 1;
	  break;
        }
      src++;
    }
}


static void
set_userid_flags (GpgmeKey key, const char *src)
{
  struct user_id_s *uid = key->last_uid;

  assert (uid);
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'r':
	  uid->revoked = 1;
	  break;
	  
	case 'i':
	  uid->invalid = 1;
	  break;

	case 'n':
	  uid->validity = GPGME_VALIDITY_NEVER;
	  break;

	case 'm':
	  uid->validity = GPGME_VALIDITY_MARGINAL;
	  break;

	case 'f':
	  uid->validity = GPGME_VALIDITY_FULL;
	  break;

	case 'u':
	  uid->validity = GPGME_VALIDITY_ULTIMATE;
	  break;
        }
      src++;
    }
}


static void
set_subkey_trust_info (struct subkey_s *subkey, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'e':
	  subkey->flags.expired = 1;
	  break;

	case 'r':
	  subkey->flags.revoked = 1;
	  break;

	case 'd':
	  subkey->flags.disabled = 1;
	  break;

	case 'i':
	  subkey->flags.invalid = 1;
	  break;
        }
      src++;
    }
}


static void
set_mainkey_capability (GpgmeKey key, const char *src)
{
  while (*src)
    {
      switch (*src)
	{
	case 'e':
	  key->keys.flags.can_encrypt = 1;
	  break;

	case 's':
	  key->keys.flags.can_sign = 1;
	  break;

	case 'c':
	  key->keys.flags.can_certify = 1;
	  break;

        case 'd':
        case 'D':
          /* Note, that this flag is also set using the key validity
             field for backward compatibility with gpg 1.2.  We use d
             and D, so that a future gpg version will be able to
             disable certain subkeys. Currently it is expected that
             gpg sets this for the primary key. */
       	  key->keys.flags.disabled = 1;
          break;

	case 'E':
	  key->gloflags.can_encrypt = 1;
	  break;

	case 'S':
	  key->gloflags.can_sign = 1;
	  break;

	case 'C':
	  key->gloflags.can_certify = 1;
	  break;
        }
      src++;
    }
}


static void
set_subkey_capability (struct subkey_s *subkey, const char *src)
{
  while (*src)
    {
      switch (*src)
	{
	case 'e':
	  subkey->flags.can_encrypt = 1;
	  break;

	case 's':
	  subkey->flags.can_sign = 1;
	  break;

	case 'c':
	  subkey->flags.can_certify = 1;
	  break;
        }
      src++;
    }
}

static void
set_ownertrust (GpgmeKey key, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'n':
	  key->otrust = GPGME_VALIDITY_NEVER;
	  break;

	case 'm':
	  key->otrust = GPGME_VALIDITY_MARGINAL;
	  break;

	case 'f':
	  key->otrust = GPGME_VALIDITY_FULL;
	  break;

	case 'u':
	  key->otrust = GPGME_VALIDITY_ULTIMATE;
	  break;

        default:
	  key->otrust = GPGME_VALIDITY_UNKNOWN;
	  break;
        }
      src++;
    }
}


/* We have read an entire key into ctx->tmp_key and should now finish
   it.  It is assumed that this releases ctx->tmp_key.  */
static void
finish_key (GpgmeCtx ctx)
{
  GpgmeKey key = ctx->tmp_key;

  ctx->tmp_key = NULL;

  if (key)
    _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_NEXT_KEY, key);
}


/* Note: We are allowed to modify LINE.  */
static GpgmeError
keylist_colon_handler (GpgmeCtx ctx, char *line)
{
  enum
    {
      RT_NONE, RT_SIG, RT_UID, RT_SUB, RT_PUB, RT_FPR, RT_SSB, RT_SEC,
      RT_CRT, RT_CRS, RT_REV
    }
  rectype = RT_NONE;
#define NR_FIELDS 13
  char *field[NR_FIELDS];
  int fields = 0;
  GpgmeKey key = ctx->tmp_key;
  struct subkey_s *subkey = NULL;
  struct certsig_s *certsig = NULL;

  DEBUG3 ("keylist_colon_handler ctx = %p, key = %p, line = %s\n",
	  ctx, key, line ? line : "(null)");

  if (!line)
    {
      /* End Of File.  */
      finish_key (ctx);
      return 0;
    }

  while (line && fields < NR_FIELDS)
    {
      field[fields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }

  if (!strcmp (field[0], "sig"))
    rectype = RT_SIG;
  else if (!strcmp (field[0], "rev"))
    rectype = RT_REV;
  else if (!strcmp (field[0], "uid") && key)
    rectype = RT_UID;
  else if (!strcmp (field[0], "sub") && key)
    {
      /* Start a new subkey.  */
      rectype = RT_SUB; 
      if (!(subkey = _gpgme_key_add_subkey (key)))
	return GPGME_Out_Of_Core;
    }
  else if (!strcmp (field[0], "ssb") && key)
    {
      /* Start a new secret subkey.  */
      rectype = RT_SSB;
      if (!(subkey = _gpgme_key_add_secret_subkey (key)))
	return GPGME_Out_Of_Core;
    }
  else if (!strcmp (field[0], "pub"))
    {
      /* Start a new keyblock.  */
      if (_gpgme_key_new (&key))
	/* The only kind of error we can get.  */
	return GPGME_Out_Of_Core;
      rectype = RT_PUB;
      finish_key (ctx);
      assert (!ctx->tmp_key);
      ctx->tmp_key = key;
    }
  else if (!strcmp (field[0], "sec"))
    {
      /* Start a new keyblock,  */
      if (_gpgme_key_new_secret (&key))
	return GPGME_Out_Of_Core;
      rectype = RT_SEC;
      finish_key (ctx);
      assert (!ctx->tmp_key);
      ctx->tmp_key = key;
    }
  else if (!strcmp (field[0], "crt"))
    {
      /* Start a new certificate.  */
      if (_gpgme_key_new (&key))
	return GPGME_Out_Of_Core;
      key->x509 = 1;
      rectype = RT_CRT;
      finish_key (ctx);
      assert (!ctx->tmp_key);
      ctx->tmp_key = key;
    }
  else if (!strcmp (field[0], "crs"))
    {
      /* Start a new certificate.  */
      if (_gpgme_key_new_secret (&key))
	return GPGME_Out_Of_Core;
      key->x509 = 1;
      rectype = RT_CRS;
      finish_key (ctx);
      assert (!ctx->tmp_key);
      ctx->tmp_key = key;
    }
  else if (!strcmp (field[0], "fpr") && key) 
    rectype = RT_FPR;
  else 
    rectype = RT_NONE;

  /* Only look at signatures immediately following a user ID.  For
     this, clear the user ID pointer when encountering anything but a
     signature.  */
  if (rectype != RT_SIG && rectype != RT_REV)
    ctx->tmp_uid = NULL;

  switch (rectype)
    {
    case RT_CRT:
    case RT_CRS:
      /* Field 8 has the X.509 serial number.  */
      if (fields >= 8)
	{
	  key->issuer_serial = strdup (field[7]);
	  if (!key->issuer_serial)
	    return GPGME_Out_Of_Core;
	}

      /* Field 10 is not used for gpg due to --fixed-list-mode option
	 but GPGSM stores the issuer name.  */
      if (fields >= 10 && _gpgme_decode_c_string (field[9],
						  &key->issuer_name, 0))
	return GPGME_Out_Of_Core;
      /* Fall through!  */

    case RT_PUB:
    case RT_SEC:
      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_mainkey_trust_info (key, field[1]);

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    key->keys.key_len = i; 
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    key->keys.key_algo = i;
	}

      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(key->keys.keyid) - 1)
	strcpy (key->keys.keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	key->keys.timestamp = parse_timestamp (field[5]);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	key->keys.expires_at = parse_timestamp (field[6]);

      /* Field 9 has the ownertrust.  */
      if (fields >= 9)
	set_ownertrust (key, field[8]);

      /* Field 11 has the signature class.  */

      /* Field 12 has the capabilities.  */
      if (fields >= 12)
	set_mainkey_capability (key, field[11]);
      break;

    case RT_SUB:
    case RT_SSB:
      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_subkey_trust_info (subkey, field[1]);

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    subkey->key_len = i;
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    subkey->key_algo = i;
	}

      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(subkey->keyid) - 1)
	strcpy (subkey->keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	subkey->timestamp = parse_timestamp (field[5]);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	subkey->expires_at = parse_timestamp (field[6]);

      /* Field 8 is reserved (LID).  */
      /* Field 9 has the ownertrust.  */
      /* Field 10, the user ID, is n/a for a subkey.  */
      
      /* Field 11 has the signature class.  */

      /* Field 12 has the capabilities.  */
      if (fields >= 12)
	set_subkey_capability (subkey, field[11]);
      break;

    case RT_UID:
      /* Field 2 has the trust info, and field 10 has the user ID.  */
      if (fields >= 10)
	{
	  if (_gpgme_key_append_name (key, field[9]))
	    return GPGME_Out_Of_Core;
	  else
	    {
	      if (field[1])
		set_userid_flags (key, field[1]);
	      ctx->tmp_uid = key->last_uid;
	    }
	}
      break;

    case RT_FPR:
      /* Field 10 has the fingerprint (take only the first one).  */
      if (fields >= 10 && !key->keys.fingerprint && field[9] && *field[9])
	{
	  key->keys.fingerprint = strdup (field[9]);
	  if (!key->keys.fingerprint)
	    return GPGME_Out_Of_Core;
	}

      /* Field 13 has the gpgsm chain ID (take only the first one).  */
      if (fields >= 13 && !key->chain_id && *field[12])
	{
	  key->chain_id = strdup (field[12]);
	  if (!key->chain_id)
	    return GPGME_Out_Of_Core;
	}
      break;

    case RT_SIG:
    case RT_REV:
      if (!ctx->tmp_uid)
	return 0;

      /* Start a new (revoked) signature.  */
      assert (ctx->tmp_uid == key->last_uid);
      certsig = _gpgme_key_add_certsig (key, (fields >= 10) ? field[9] : NULL);
      if (!certsig)
	return GPGME_Out_Of_Core;

      /* Field 2 has the calculated trust ('!', '-', '?', '%').  */
      if (fields >= 2)
	switch (field[1][0])
	  {
	  case '!':
	    certsig->sig_stat = GPGME_SIG_STAT_GOOD;
	    break;

	  case '-':
	    certsig->sig_stat = GPGME_SIG_STAT_BAD;
	    break;

	  case '?':
	    certsig->sig_stat = GPGME_SIG_STAT_NOKEY;
	    break;

	  case '%':
	    certsig->sig_stat = GPGME_SIG_STAT_ERROR;
	    break;

	  default:
	    certsig->sig_stat = GPGME_SIG_STAT_NONE;
	    break;
	  }

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    certsig->algo = i;
	}
      
      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(certsig->keyid) - 1)
	strcpy (certsig->keyid, field[4]);
      
      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	certsig->timestamp = parse_timestamp (field[5]);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	certsig->expires_at = parse_timestamp (field[6]);

      /* Field 11 has the signature class (eg, 0x30 means revoked).  */
      if (fields >= 11)
	if (field[10][0] && field[10][1])
	  {
	    int class = _gpgme_hextobyte (field[10]);
	    if (class >= 0)
	      {
		certsig->sig_class = class;
		if (class == 0x30)
		  certsig->flags.revoked = 1;
	      }
	    if (field[10][2] == 'x')
	      certsig->flags.exportable = 1;
	  }
      break;

    case RT_NONE:
      /* Unknown record.  */
      break;
    }
  return 0;
}


void
_gpgme_op_keylist_event_cb (void *data, GpgmeEventIO type, void *type_data)
{
  GpgmeCtx ctx = (GpgmeCtx) data;
  GpgmeKey key = (GpgmeKey) type_data;
  struct key_queue_item_s *q, *q2;

  assert (type == GPGME_EVENT_NEXT_KEY);

  _gpgme_key_cache_add (key);

  q = malloc (sizeof *q);
  if (!q)
    {
      gpgme_key_release (key);
      /* FIXME       return GPGME_Out_Of_Core; */
      return;
    }
  q->key = key;
  q->next = NULL;
  /* FIXME: Lock queue.  Use a tail pointer?  */
  if (!(q2 = ctx->key_queue))
    ctx->key_queue = q;
  else
    {
      for (; q2->next; q2 = q2->next)
	;
      q2->next = q;
    }
  ctx->key_cond = 1;
  /* FIXME: Unlock queue.  */
}


/**
 * gpgme_op_keylist_start:
 * @c: context 
 * @pattern: a GnuPG user ID or NULL for all
 * @secret_only: List only keys where the secret part is available
 * 
 * Note that this function also cancels a pending key listing
 * operaton. To actually retrieve the key, use
 * gpgme_op_keylist_next().
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_keylist_start (GpgmeCtx ctx, const char *pattern, int secret_only)
{
  GpgmeError err = 0;

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    goto leave;

  gpgme_key_release (ctx->tmp_key);
  ctx->tmp_key = NULL;
  /* Fixme: Release key_queue.  */

  _gpgme_engine_set_status_handler (ctx->engine, keylist_status_handler, ctx);
  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      keylist_colon_handler, ctx);
  if (err)
    goto leave;

  /* We don't want to use the verbose mode as this will also print the
     key signatures which is in most cases not needed and furthermore
     we just ignore those lines - This should speed up things.  */
  _gpgme_engine_set_verbosity (ctx->engine, 0);

  err = _gpgme_engine_op_keylist (ctx->engine, pattern, secret_only,
				  ctx->keylist_mode);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


/**
 * gpgme_op_keylist_ext_start:
 * @c: context 
 * @pattern: a NULL terminated array of search patterns
 * @secret_only: List only keys where the secret part is available
 * @reserved: Should be 0.
 * 
 * Note that this function also cancels a pending key listing
 * operaton. To actually retrieve the key, use
 * gpgme_op_keylist_next().
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_keylist_ext_start (GpgmeCtx ctx, const char *pattern[],
			    int secret_only, int reserved)
{
  GpgmeError err = 0;

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    goto leave;

  gpgme_key_release (ctx->tmp_key);
  ctx->tmp_key = NULL;

  _gpgme_engine_set_status_handler (ctx->engine, keylist_status_handler, ctx);
  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      keylist_colon_handler, ctx);
  if (err)
    goto leave;

  /* We don't want to use the verbose mode as this will also print the
     key signatures which is in most cases not needed and furthermore
     we just ignore those lines - This should speed up things.  */
  _gpgme_engine_set_verbosity (ctx->engine, 0);

  err = _gpgme_engine_op_keylist_ext (ctx->engine, pattern, secret_only,
				      reserved, ctx->keylist_mode);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


/**
 * gpgme_op_keylist_next:
 * @c: Context
 * @r_key: Returned key object
 * 
 * Return the next key from the key listing started with
 * gpgme_op_keylist_start().  The caller must free the key using
 * gpgme_key_release().  If the last key has already been returned the
 * last time the function was called, %GPGME_EOF is returned and the
 * operation is finished.
 * 
 * Return value: 0 on success, %GPGME_EOF or another error code.
 **/
GpgmeError
gpgme_op_keylist_next (GpgmeCtx ctx, GpgmeKey *r_key)
{
  struct key_queue_item_s *queue_item;

  if (!r_key)
    return GPGME_Invalid_Value;
  *r_key = NULL;
  if (!ctx)
    return GPGME_Invalid_Value;
  if (!ctx->pending)
    return GPGME_No_Request;

  if (!ctx->key_queue)
    {
      GpgmeError err = _gpgme_wait_on_condition (ctx, &ctx->key_cond);
      if (err)
	{
	  ctx->pending = 0;
	  return err;
	}
      if (!ctx->pending)
	{
	  /* The operation finished.  Because not all keys might have
	     been returned to the caller yet, we just reset the
	     pending flag to 1.  This will cause us to call
	     _gpgme_wait_on_condition without any active file
	     descriptors, but that is a no-op, so it is safe.  */
	  ctx->pending = 1;
	}
      if (!ctx->key_cond)
	{
	  ctx->pending = 0;
	  return GPGME_EOF;
	}
      ctx->key_cond = 0; 
      assert (ctx->key_queue);
    }
  queue_item = ctx->key_queue;
  ctx->key_queue = queue_item->next;
  if (!ctx->key_queue)
    ctx->key_cond = 0;
  
  *r_key = queue_item->key;
  free (queue_item);
  return 0;
}


/**
 * gpgme_op_keylist_end:
 * @c: Context
 * 
 * Ends the keylist operation and allows to use the context for some
 * other operation next.
 **/
GpgmeError
gpgme_op_keylist_end (GpgmeCtx ctx)
{
  if (!ctx)
    return GPGME_Invalid_Value;
  if (!ctx->pending)
    return GPGME_No_Request;

  ctx->pending = 0;
  return 0;
}

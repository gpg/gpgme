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
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "context.h"
#include "ops.h"
#include "debug.h"


struct key_queue_item_s
{
  struct key_queue_item_s *next;
  gpgme_key_t key;
};

typedef struct
{
  struct _gpgme_op_keylist_result result;

  gpgme_key_t tmp_key;
  gpgme_user_id_t tmp_uid;
  /* Something new is available.  */
  int key_cond;
  struct key_queue_item_s *key_queue;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  struct key_queue_item_s *key = opd->key_queue;

  if (opd->tmp_key)
    gpgme_key_unref (opd->tmp_key);
  if (opd->tmp_uid)
    free (opd->tmp_uid);
  while (key)
    {
      struct key_queue_item_s *next = key->next;

      gpgme_key_unref (key->key);
      key = next;
    }
}


gpgme_keylist_result_t
gpgme_op_keylist_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    return NULL;

  return &opd->result;
}


static gpgme_error_t
keylist_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_TRUNCATED:
      opd->result.truncated = 1;
      break;

    default:
      break;
    }
  return 0;
}



static void
set_mainkey_trust_info (gpgme_key_t key, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'e':
	  key->subkeys->expired = 1;
	  break;

	case 'r':
	  key->subkeys->revoked = 1;
	  break;

	case 'd':
          /* Note that gpg 1.3 won't print that anymore but only uses
             the capabilities field. */
	  key->subkeys->disabled = 1;
	  break;

	case 'i':
	  key->subkeys->invalid = 1;
	  break;
        }
      src++;
    }
}


static void
set_userid_flags (gpgme_key_t key, const char *src)
{
  gpgme_user_id_t uid = key->_last_uid;

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
set_subkey_trust_info (gpgme_subkey_t subkey, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'e':
	  subkey->expired = 1;
	  break;

	case 'r':
	  subkey->revoked = 1;
	  break;

	case 'd':
	  subkey->disabled = 1;
	  break;

	case 'i':
	  subkey->invalid = 1;
	  break;
        }
      src++;
    }
}


static void
set_mainkey_capability (gpgme_key_t key, const char *src)
{
  while (*src)
    {
      switch (*src)
	{
	case 'e':
	  key->subkeys->can_encrypt = 1;
	  break;

	case 's':
	  key->subkeys->can_sign = 1;
	  break;

	case 'c':
	  key->subkeys->can_certify = 1;
	  break;

	case 'a':
	  key->subkeys->can_authenticate = 1;
	  break;

        case 'd':
        case 'D':
          /* Note, that this flag is also set using the key validity
             field for backward compatibility with gpg 1.2.  We use d
             and D, so that a future gpg version will be able to
             disable certain subkeys. Currently it is expected that
             gpg sets this for the primary key. */
       	  key->subkeys->disabled = 1;
          break;

	case 'E':
	  key->can_encrypt = 1;
	  break;

	case 'S':
	  key->can_sign = 1;
	  break;

	case 'C':
	  key->can_certify = 1;
	  break;

	case 'A':
	  key->can_authenticate = 1;
	  break;
        }
      src++;
    }
}


static void
set_subkey_capability (gpgme_subkey_t subkey, const char *src)
{
  while (*src)
    {
      switch (*src)
	{
	case 'e':
	  subkey->can_encrypt = 1;
	  break;

	case 's':
	  subkey->can_sign = 1;
	  break;

	case 'c':
	  subkey->can_certify = 1;
	  break;

	case 'a':
	  subkey->can_authenticate = 1;
	  break;
        }
      src++;
    }
}

static void
set_ownertrust (gpgme_key_t key, const char *src)
{
  /* Look at letters and stop at the first digit.  */
  while (*src && !isdigit (*src))
    {
      switch (*src)
	{
	case 'n':
	  key->owner_trust = GPGME_VALIDITY_NEVER;
	  break;

	case 'm':
	  key->owner_trust = GPGME_VALIDITY_MARGINAL;
	  break;

	case 'f':
	  key->owner_trust = GPGME_VALIDITY_FULL;
	  break;

	case 'u':
	  key->owner_trust = GPGME_VALIDITY_ULTIMATE;
	  break;

        default:
	  key->owner_trust = GPGME_VALIDITY_UNKNOWN;
	  break;
        }
      src++;
    }
}


/* We have read an entire key into tmp_key and should now finish it.
   It is assumed that this releases tmp_key.  */
static void
finish_key (gpgme_ctx_t ctx, op_data_t opd)
{
  gpgme_key_t key = opd->tmp_key;

  opd->tmp_key = NULL;
  opd->tmp_uid = NULL;

  if (key)
    _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_NEXT_KEY, key);
}


/* Note: We are allowed to modify LINE.  */
static gpgme_error_t
keylist_colon_handler (void *priv, char *line)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  enum
    {
      RT_NONE, RT_SIG, RT_UID, RT_SUB, RT_PUB, RT_FPR,
      RT_SSB, RT_SEC, RT_CRT, RT_CRS, RT_REV
    }
  rectype = RT_NONE;
#define NR_FIELDS 13
  char *field[NR_FIELDS];
  int fields = 0;
  void *hook;
  op_data_t opd;
  gpgme_error_t err;
  gpgme_key_t key;
  gpgme_subkey_t subkey = NULL;
  gpgme_key_sig_t keysig = NULL;

  DEBUG3 ("keylist_colon_handler ctx = %p, key = %p, line = %s\n",
	  ctx, key, line ? line : "(null)");

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  key = opd->tmp_key;

  if (!line)
    {
      /* End Of File.  */
      finish_key (ctx, opd);
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
  else if (!strcmp (field[0], "pub"))
    rectype = RT_PUB;
  else if (!strcmp (field[0], "sec"))
    rectype = RT_SEC;
  else if (!strcmp (field[0], "crt"))
    rectype = RT_CRT;
  else if (!strcmp (field[0], "crs"))
    rectype = RT_CRS;
  else if (!strcmp (field[0], "fpr") && key) 
    rectype = RT_FPR;
  else if (!strcmp (field[0], "uid") && key)
    rectype = RT_UID;
  else if (!strcmp (field[0], "sub") && key)
    rectype = RT_SUB; 
  else if (!strcmp (field[0], "ssb") && key)
    rectype = RT_SSB;
  else 
    rectype = RT_NONE;

  /* Only look at signatures immediately following a user ID.  For
     this, clear the user ID pointer when encountering anything but a
     signature.  */
  if (rectype != RT_SIG && rectype != RT_REV)
    opd->tmp_uid = NULL;

  switch (rectype)
    {
    case RT_PUB:
    case RT_SEC:
    case RT_CRT:
    case RT_CRS:
      /* Start a new keyblock.  */
      err = _gpgme_key_new (&key);
      if (err)
	return err;
      err = _gpgme_key_add_subkey (key, &subkey);
      if (err)
	{
	  gpgme_key_unref (key);
	  return err;
	}

      if (rectype == RT_SEC || rectype == RT_CRS)
	key->secret = 1;
      if (rectype == RT_CRT || rectype == RT_CRS)
	key->protocol = GPGME_PROTOCOL_CMS;
      finish_key (ctx, opd);
      opd->tmp_key = key;

      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_mainkey_trust_info (key, field[1]);

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    subkey->length = i; 
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    subkey->pubkey_algo = i;
	}

      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(subkey->_keyid) - 1)
	strcpy (subkey->_keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	subkey->timestamp = _gpgme_parse_timestamp (field[5], NULL);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	subkey->expires = _gpgme_parse_timestamp (field[6], NULL);

      /* Field 8 has the X.509 serial number.  */
      if (fields >= 8 && (rectype == RT_CRT || rectype == RT_CRS))
	{
	  key->issuer_serial = strdup (field[7]);
	  if (!key->issuer_serial)
	    return gpg_error_from_errno (errno);
	}
	  
      /* Field 9 has the ownertrust.  */
      if (fields >= 9)
	set_ownertrust (key, field[8]);

      /* Field 10 is not used for gpg due to --fixed-list-mode option
	 but GPGSM stores the issuer name.  */
      if (fields >= 10 && (rectype == RT_CRT || rectype == RT_CRS))
	if (_gpgme_decode_c_string (field[9], &key->issuer_name, 0))
	  return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */

      /* Field 11 has the signature class.  */

      /* Field 12 has the capabilities.  */
      if (fields >= 12)
	set_mainkey_capability (key, field[11]);
      break;

    case RT_SUB:
    case RT_SSB:
      /* Start a new subkey.  */
      err = _gpgme_key_add_subkey (key, &subkey);
      if (err)
	return err;

      if (rectype == RT_SSB)
	subkey->secret = 1;

      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_subkey_trust_info (subkey, field[1]);

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    subkey->length = i;
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    subkey->pubkey_algo = i;
	}

      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(subkey->_keyid) - 1)
	strcpy (subkey->_keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	subkey->timestamp = _gpgme_parse_timestamp (field[5], NULL);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	subkey->expires = _gpgme_parse_timestamp (field[6], NULL);

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
	    return gpg_error_from_errno (GPG_ERR_ENOMEM);	/* FIXME */
	  else
	    {
	      if (field[1])
		set_userid_flags (key, field[1]);
	      opd->tmp_uid = key->_last_uid;
	    }
	}
      break;

    case RT_FPR:
      /* Field 10 has the fingerprint (take only the first one).  */
      if (fields >= 10 && !key->subkeys->fpr && field[9] && *field[9])
	{
	  key->subkeys->fpr = strdup (field[9]);
	  if (!key->subkeys->fpr)
	    return gpg_error_from_errno (errno);
	}

      /* Field 13 has the gpgsm chain ID (take only the first one).  */
      if (fields >= 13 && !key->chain_id && *field[12])
	{
	  key->chain_id = strdup (field[12]);
	  if (!key->chain_id)
	    return gpg_error_from_errno (errno);
	}
      break;

    case RT_SIG:
    case RT_REV:
      if (!opd->tmp_uid)
	return 0;

      /* Start a new (revoked) signature.  */
      assert (opd->tmp_uid == key->_last_uid);
      keysig = _gpgme_key_add_sig (key, (fields >= 10) ? field[9] : NULL);
      if (!keysig)
	return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */

      /* Field 2 has the calculated trust ('!', '-', '?', '%').  */
      if (fields >= 2)
	switch (field[1][0])
	  {
	  case '!':
	    keysig->status = gpg_error (GPG_ERR_NO_ERROR);
	    break;

	  case '-':
	    keysig->status = gpg_error (GPG_ERR_BAD_SIGNATURE);
	    break;

	  case '?':
	    keysig->status = gpg_error (GPG_ERR_NO_PUBKEY);
	    break;

	  case '%':
	    keysig->status = gpg_error (GPG_ERR_GENERAL);
	    break;

	  default:
	    keysig->status = gpg_error (GPG_ERR_NO_ERROR);
	    break;
	  }

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    keysig->pubkey_algo = i;
	}
      
      /* Field 5 has the long keyid.  */
      if (fields >= 5 && strlen (field[4]) == DIM(keysig->_keyid) - 1)
	strcpy (keysig->_keyid, field[4]);
      
      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	keysig->timestamp = _gpgme_parse_timestamp (field[5], NULL);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	keysig->expires = _gpgme_parse_timestamp (field[6], NULL);

      /* Field 11 has the signature class (eg, 0x30 means revoked).  */
      if (fields >= 11)
	if (field[10][0] && field[10][1])
	  {
	    int sig_class = _gpgme_hextobyte (field[10]);
	    if (sig_class >= 0)
	      {
		keysig->sig_class = sig_class;
		keysig->class = keysig->sig_class;
		if (sig_class == 0x30)
		  keysig->revoked = 1;
	      }
	    if (field[10][2] == 'x')
	      keysig->exportable = 1;
	  }
      break;

    case RT_NONE:
      /* Unknown record.  */
      break;
    }
  return 0;
}


void
_gpgme_op_keylist_event_cb (void *data, gpgme_event_io_t type, void *type_data)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx = (gpgme_ctx_t) data;
  gpgme_key_t key = (gpgme_key_t) type_data;
  void *hook;
  op_data_t opd;
  struct key_queue_item_s *q, *q2;

  assert (type == GPGME_EVENT_NEXT_KEY);

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return;

  q = malloc (sizeof *q);
  if (!q)
    {
      gpgme_key_unref (key);
      /* FIXME       return GPGME_Out_Of_Core; */
      return;
    }
  q->key = key;
  q->next = NULL;
  /* FIXME: Use a tail pointer?  */
  if (!(q2 = opd->key_queue))
    opd->key_queue = q;
  else
    {
      for (; q2->next; q2 = q2->next)
	;
      q2->next = q;
    }
  opd->key_cond = 1;
}


/* Start a keylist operation within CTX, searching for keys which
   match PATTERN.  If SECRET_ONLY is true, only secret keys are
   returned.  */
gpgme_error_t
gpgme_op_keylist_start (gpgme_ctx_t ctx, const char *pattern, int secret_only)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, keylist_status_handler, ctx);

  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      keylist_colon_handler, ctx);
  if (err)
    return err;

  return _gpgme_engine_op_keylist (ctx->engine, pattern, secret_only,
				   ctx->keylist_mode);
}


/* Start a keylist operation within CTX, searching for keys which
   match PATTERN.  If SECRET_ONLY is true, only secret keys are
   returned.  */
gpgme_error_t
gpgme_op_keylist_ext_start (gpgme_ctx_t ctx, const char *pattern[],
			    int secret_only, int reserved)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, 2);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, keylist_status_handler, ctx);
  err = _gpgme_engine_set_colon_line_handler (ctx->engine,
					      keylist_colon_handler, ctx);
  if (err)
    return err;

  return _gpgme_engine_op_keylist_ext (ctx->engine, pattern, secret_only,
				       reserved, ctx->keylist_mode);
}


/* Return the next key from the keylist in R_KEY.  */
gpgme_error_t
gpgme_op_keylist_next (gpgme_ctx_t ctx, gpgme_key_t *r_key)
{
  gpgme_error_t err;
  struct key_queue_item_s *queue_item;
  void *hook;
  op_data_t opd;

  if (!ctx || !r_key)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_key = NULL;
  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_op_data_lookup (ctx, OPDATA_KEYLIST, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  if (!opd->key_queue)
    {
      err = _gpgme_wait_on_condition (ctx, &opd->key_cond);
      if (err)
	return err;

      if (!opd->key_cond)
	return gpg_error (GPG_ERR_EOF);

      opd->key_cond = 0; 
      assert (opd->key_queue);
    }
  queue_item = opd->key_queue;
  opd->key_queue = queue_item->next;
  if (!opd->key_queue)
    opd->key_cond = 0;
  
  *r_key = queue_item->key;
  free (queue_item);
  return 0;
}


/* Terminate a pending keylist operation within CTX.  */
gpgme_error_t
gpgme_op_keylist_end (gpgme_ctx_t ctx)
{
  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  return 0;
}


/* Get the key with the fingerprint FPR from the crypto backend.  If
   SECRET is true, get the secret key.  */
gpgme_error_t
gpgme_get_key (gpgme_ctx_t ctx, const char *fpr, gpgme_key_t *r_key,
	       int secret)
{
  gpgme_ctx_t listctx;
  gpgme_error_t err;
  gpgme_key_t key;

  if (!ctx || !r_key)
    return gpg_error (GPG_ERR_INV_VALUE);
  
  if (strlen (fpr) < 16)	/* We have at least a key ID.  */
    return gpg_error (GPG_ERR_INV_VALUE);

  /* FIXME: We use our own context because we have to avoid the user's
     I/O callback handlers.  */
  err = gpgme_new (&listctx);
  if (err)
    return err;
  gpgme_set_protocol (listctx, gpgme_get_protocol (ctx));
  gpgme_set_keylist_mode (listctx, ctx->keylist_mode);
  err = gpgme_op_keylist_start (listctx, fpr, secret);
  if (!err)
    err = gpgme_op_keylist_next (listctx, r_key);
  if (!err)
    {
      err = gpgme_op_keylist_next (listctx, &key);
      if (gpgme_err_code (err) == GPG_ERR_EOF)
	err = gpg_error (GPG_ERR_NO_ERROR);
      else
	{
	  if (!err)
	    {
	      gpgme_key_unref (key);
	      err = gpg_error (GPG_ERR_AMBIGUOUS_NAME);
	    }
	  gpgme_key_unref (*r_key);
	}
    }
  gpgme_release (listctx);
  return err;
}

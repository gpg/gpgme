/* verify.c - Signature verification.
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
#include <errno.h>

#include "gpgme.h"
#include "util.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_verify_result result;

  gpgme_signature_t current_sig;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_signature_t sig = opd->result.signatures;

  while (sig)
    {
      gpgme_signature_t next = sig->next;
      gpgme_sig_notation_t notation = sig->notations;

      while (notation)
	{
	  gpgme_sig_notation_t next_nota = notation->next;

	  if (notation->name)
	    free (notation->name);
	  if (notation->value)
	    free (notation->value);
	  notation = next_nota;
	}

      if (sig->fpr)
	free (sig->fpr);
      free (sig);
      sig = next;
    }
}


gpgme_verify_result_t
gpgme_op_verify_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    return NULL;

  return &opd->result;
}


/* Build a summary vector from RESULT. */
static void
calc_sig_summary (gpgme_signature_t sig)
{
  unsigned long sum = 0;

  if (sig->validity == GPGME_VALIDITY_FULL
      || sig->validity == GPGME_VALIDITY_ULTIMATE)
    {
      if (gpg_err_code (sig->status) == GPG_ERR_NO_ERROR
	  || gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED
	  || gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED)
	sum |= GPGME_SIGSUM_GREEN;
    }
  else if (sig->validity == GPGME_VALIDITY_NEVER)
    {
      if (gpg_err_code (sig->status) == GPG_ERR_NO_ERROR
	  || gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED
	  || gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED)
	sum |= GPGME_SIGSUM_RED;
    }
  else if (gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE)
    sum |= GPGME_SIGSUM_RED;
  
  /* FIXME: handle the case when key and message are expired. */
  switch (gpg_err_code (sig->status))
    {
    case GPG_ERR_SIG_EXPIRED:
      sum |= GPGME_SIGSUM_SIG_EXPIRED;
      break;

    case GPG_ERR_KEY_EXPIRED:
      sum |= GPGME_SIGSUM_KEY_EXPIRED;
      break;

    case GPG_ERR_NO_PUBKEY:
      sum |= GPGME_SIGSUM_KEY_MISSING;
      break;

    case GPG_ERR_BAD_SIGNATURE:
    case GPG_ERR_NO_ERROR:
      break;

    default:
      sum |= GPGME_SIGSUM_SYS_ERROR;
      break;
    }
  
  if (sig->wrong_key_usage)
    sum |= GPGME_SIGSUM_BAD_POLICY;
  
  /* Set the valid flag when the signature is unquestionable
     valid. */
  if ((sum & GPGME_SIGSUM_GREEN) && !(sum & ~GPGME_SIGSUM_GREEN))
    sum |= GPGME_SIGSUM_VALID;
  
  sig->summary = sum;
}
  

static gpgme_error_t
parse_new_sig (op_data_t opd, gpgme_status_code_t code, char *args)
{
  gpgme_signature_t sig;
  char *end = strchr (args, ' ');

  if (end)
    {
      *end = '\0';
      end++;
    }

  sig = calloc (1, sizeof (*sig));
  if (!sig)
    return gpg_error_from_errno (errno);
  if (!opd->result.signatures)
    opd->result.signatures = sig;
  if (opd->current_sig)
    opd->current_sig->next = sig;
  opd->current_sig = sig;

  /* FIXME: We should set the source of the state.  */
  switch (code)
    {
    case GPGME_STATUS_GOODSIG:
      sig->status = gpg_error (GPG_ERR_NO_ERROR);
      break;

    case GPGME_STATUS_EXPSIG:
      sig->status = gpg_error (GPG_ERR_SIG_EXPIRED);
      break;

    case GPGME_STATUS_EXPKEYSIG:
      sig->status = gpg_error (GPG_ERR_KEY_EXPIRED);
      break;

    case GPGME_STATUS_BADSIG:
      sig->status = gpg_error (GPG_ERR_BAD_SIGNATURE);
      break;

    case GPGME_STATUS_ERRSIG:
      if (end)
	{
	  int i = 0;
	  /* The return code is the 6th argument, if it is 9, the
	     problem is a missing key.  */
	  while (end && i < 4)
	    {
	      end = strchr (end, ' ');
	      if (end)
		end++;
	      i++;
	    }
	  if (end && end[0] && (!end[1] || end[1] == ' '))
	    {
	      switch (end[0])
		{
		case '4':
		  sig->status = gpg_error (GPG_ERR_UNSUPPORTED_ALGORITHM);
		  break;
		  
		case '9':
		  sig->status = gpg_error (GPG_ERR_NO_PUBKEY);
		  break;
		  
		default:
		  sig->status = gpg_error (GPG_ERR_GENERAL);
		}
	    }
	}
      else
	sig->status = gpg_error (GPG_ERR_GENERAL);
      break;

    default:
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (*args)
    {
      sig->fpr = strdup (args);
      if (!sig->fpr)
	return gpg_error_from_errno (errno);
    }
  return 0;
}


static gpgme_error_t
parse_valid_sig (gpgme_signature_t sig, char *args)
{
  char *end = strchr (args, ' ');

  if (end)
    {
      *end = '\0';
      end++;
    }

  if (!*args)
    /* We require at least the fingerprint.  */
    return gpg_error (GPG_ERR_GENERAL);

  if (sig->fpr)
    free (sig->fpr);
  sig->fpr = strdup (args);
  if (!sig->fpr)
    return gpg_error_from_errno (errno);

  end = strchr (end, ' ');
  if (end)
    {
      char *tail;

      sig->timestamp = _gpgme_parse_timestamp (end, &tail);
      if (sig->timestamp == -1 || end == tail || (*tail && *tail != ' '))
	return gpg_error (GPG_ERR_INV_ENGINE);
      end = tail;
     
      sig->exp_timestamp = _gpgme_parse_timestamp (end, &tail);
      if (sig->exp_timestamp == -1 || end == tail || (*tail && *tail != ' '))
	return gpg_error (GPG_ERR_INV_ENGINE);
    }
  return 0;
}


static gpgme_error_t
parse_notation (gpgme_signature_t sig, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;
  gpgme_sig_notation_t *lastp = &sig->notations;
  gpgme_sig_notation_t notation = sig->notations;
  char *end = strchr (args, ' ');

  if (end)
    *end = '\0';

  if (code == GPGME_STATUS_NOTATION_NAME || code == GPGME_STATUS_POLICY_URL)
    {
      /* FIXME: We could keep a pointer to the last notation in the list.  */
      while (notation && notation->value)
	{
	  lastp = &notation->next;
	  notation = notation->next;
	}

      if (notation)
	/* There is another notation name without data for the
	   previous one.  The crypto backend misbehaves.  */
	return gpg_error (GPG_ERR_INV_ENGINE);

      notation = malloc (sizeof (*sig));
      if (!notation)
	return gpg_error_from_errno (errno);
      notation->next = NULL;

      if (code == GPGME_STATUS_NOTATION_NAME)
	{
	  int len = strlen (args) + 1;

	  notation->name = malloc (len);
	  if (!notation->name)
	    {
	      int saved_errno = errno;
	      free (notation);
	      return gpg_error_from_errno (saved_errno);
	    }
	  err = _gpgme_decode_percent_string (args, &notation->name, len);
	  if (err)
	    {
	      free (notation->name);
	      free (notation);
	      return err;
	    }

	  notation->value = NULL;
	}
      else
	{
	  int len = strlen (args) + 1;

	  notation->name = NULL;
	  notation->value = malloc (len);
	  if (!notation->value)
	    {
	      int saved_errno = errno;
	      free (notation);
	      return gpg_error_from_errno (saved_errno);
	    }
	  err = _gpgme_decode_percent_string (args, &notation->value, len);
	  if (err)
	    {
	      free (notation->value);
	      free (notation);
	      return err;
	    }
	}
      *lastp = notation;
    }
  else if (code == GPGME_STATUS_NOTATION_DATA)
    {
      int len = strlen (args) + 1;
      char *dest;

      /* FIXME: We could keep a pointer to the last notation in the list.  */
      while (notation && notation->next)
	{
	  lastp = &notation->next;
	  notation = notation->next;
	}

      if (!notation || !notation->name)
	/* There is notation data without a previous notation
	   name.  The crypto backend misbehaves.  */
	return gpg_error (GPG_ERR_INV_ENGINE);
      
      if (!notation->value)
	{
	  dest = notation->value = malloc (len);
	  if (!dest)
	    return gpg_error_from_errno (errno);
	}
      else
	{
	  int cur_len = strlen (notation->value);
	  dest = realloc (notation->value, len + strlen (notation->value));
	  if (!dest)
	    return gpg_error_from_errno (errno);
	  notation->value = dest;
	  dest += cur_len;
	}
      
      err = _gpgme_decode_percent_string (args, &dest, len);
      if (err)
	return err;
    }
  else
    return gpg_error (GPG_ERR_INV_ENGINE);
  return 0;
}


static gpgme_error_t
parse_trust (gpgme_signature_t sig, gpgme_status_code_t code, char *args)
{
  char *end = strchr (args, ' ');

  if (end)
    *end = '\0';

  switch (code)
    {
    case GPGME_STATUS_TRUST_UNDEFINED:
    default:
      sig->validity = GPGME_VALIDITY_UNKNOWN;
      break;

    case GPGME_STATUS_TRUST_NEVER:
      sig->validity = GPGME_VALIDITY_NEVER;
      break;

    case GPGME_STATUS_TRUST_MARGINAL:
      sig->validity = GPGME_VALIDITY_MARGINAL;
      break;

    case GPGME_STATUS_TRUST_FULLY:
    case GPGME_STATUS_TRUST_ULTIMATE:
      sig->validity = GPGME_VALIDITY_FULL;
      break;
    }

  if (*args)
    sig->validity_reason = _gpgme_map_gnupg_error (args);

  return 0;
}


static gpgme_error_t
parse_error (gpgme_signature_t sig, char *args)
{
  gpgme_error_t err;
  char *where = strchr (args, ' ');
  char *which;

  if (where)
    {
      *where = '\0';
      which = where + 1;

      where = strchr (which, ' ');
      if (where)
	*where = '\0';

      where = args;      
    }
  else
    return gpg_error (GPG_ERR_INV_ENGINE);

  err = _gpgme_map_gnupg_error (which);

  if (!strcmp (where, "verify.findkey"))
    sig->status = err;
  else if (!strcmp (where, "verify.keyusage")
	   && gpg_err_code (err) == GPG_ERR_WRONG_KEY_USAGE)
    sig->wrong_key_usage = 1;

  return 0;
}


gpgme_error_t
_gpgme_verify_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  gpgme_signature_t sig;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  sig = opd->current_sig;

  switch (code)
    {
    case GPGME_STATUS_GOODSIG:
    case GPGME_STATUS_EXPSIG:
    case GPGME_STATUS_EXPKEYSIG:
    case GPGME_STATUS_BADSIG:
    case GPGME_STATUS_ERRSIG:
      if (sig)
	calc_sig_summary (sig);
      return parse_new_sig (opd, code, args);

    case GPGME_STATUS_VALIDSIG:
      return sig ? parse_valid_sig (sig, args)
	: gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_NODATA:
      if (!sig)
	return gpg_error (GPG_ERR_NO_DATA);
      sig->status = gpg_error (GPG_ERR_NO_DATA);
      break;

    case GPGME_STATUS_UNEXPECTED:
      if (!sig)
	return gpg_error (GPG_ERR_GENERAL);
      sig->status = gpg_error (GPG_ERR_NO_DATA);
      break;

    case GPGME_STATUS_NOTATION_NAME:
    case GPGME_STATUS_NOTATION_DATA:
    case GPGME_STATUS_POLICY_URL:
      return sig ? parse_notation (sig, code, args)
	: gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_TRUST_UNDEFINED:
    case GPGME_STATUS_TRUST_NEVER:
    case GPGME_STATUS_TRUST_MARGINAL:
    case GPGME_STATUS_TRUST_FULLY:
    case GPGME_STATUS_TRUST_ULTIMATE:
      return sig ? parse_trust (sig, code, args)
	: gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_ERROR:
      return sig ? parse_error (sig, args) : gpg_error (GPG_ERR_INV_ENGINE);

    case GPGME_STATUS_EOF:
      if (sig)
	calc_sig_summary (sig);
      break;

    default:
      break;
    }
  return 0;
}


static gpgme_error_t
verify_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_verify_status_handler (priv, code, args);
  return err;
}


gpgme_error_t
_gpgme_op_verify_init_result (gpgme_ctx_t ctx)
{  
  void *hook;
  op_data_t opd;

  return _gpgme_op_data_lookup (ctx, OPDATA_VERIFY, &hook,
				sizeof (*opd), release_op_data);
}


static gpgme_error_t
verify_start (gpgme_ctx_t ctx, int synchronous, gpgme_data_t sig,
	      gpgme_data_t signed_text, gpgme_data_t plaintext)
{
  gpgme_error_t err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_verify_init_result (ctx);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, verify_status_handler, ctx);

  if (!sig)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!signed_text && !plaintext)
    return gpg_error (GPG_ERR_INV_VALUE);

  return _gpgme_engine_op_verify (ctx->engine, sig, signed_text, plaintext);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_verify_start (gpgme_ctx_t ctx, gpgme_data_t sig,
		       gpgme_data_t signed_text, gpgme_data_t plaintext)
{
  return verify_start (ctx, 0, sig, signed_text, plaintext);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_verify (gpgme_ctx_t ctx, gpgme_data_t sig, gpgme_data_t signed_text,
		 gpgme_data_t plaintext)
{
  gpgme_error_t err;

  err = verify_start (ctx, 1, sig, signed_text, plaintext);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}


/* Compatibility interfaces.  */

/* Get the key used to create signature IDX in CTX and return it in
   R_KEY.  */
gpgme_error_t
gpgme_get_sig_key (gpgme_ctx_t ctx, int idx, gpgme_key_t *r_key)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return gpg_error (GPG_ERR_EOF);

  return gpgme_get_key (ctx, sig->fpr, r_key, 0);
}


/* Retrieve the signature status of signature IDX in CTX after a
   successful verify operation in R_STAT (if non-null).  The creation
   time stamp of the signature is returned in R_CREATED (if non-null).
   The function returns a string containing the fingerprint.  */
const char *gpgme_get_sig_status (gpgme_ctx_t ctx, int idx,
                                  _gpgme_sig_stat_t *r_stat, time_t *r_created)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return NULL;

  if (r_stat)
    {
      switch (gpg_err_code (sig->status))
	{
	case GPG_ERR_NO_ERROR:
	  *r_stat = GPGME_SIG_STAT_GOOD;
	  break;
	  
	case GPG_ERR_BAD_SIGNATURE:
	  *r_stat = GPGME_SIG_STAT_BAD;
	  break;
	  
	case GPG_ERR_NO_PUBKEY:
	  *r_stat = GPGME_SIG_STAT_NOKEY;
	  break;
	  
	case GPG_ERR_NO_DATA:
	  *r_stat = GPGME_SIG_STAT_NOSIG;
	  break;
	  
	case GPG_ERR_SIG_EXPIRED:
	  *r_stat = GPGME_SIG_STAT_GOOD_EXP;
	  break;
	  
	case GPG_ERR_KEY_EXPIRED:
	  *r_stat = GPGME_SIG_STAT_GOOD_EXPKEY;
	  break;
	  
	default:
	  *r_stat = GPGME_SIG_STAT_ERROR;
	  break;
	}
    }
  if (r_created)
    *r_created = sig->timestamp;
  return sig->fpr;
}


/* Retrieve certain attributes of a signature.  IDX is the index
   number of the signature after a successful verify operation.  WHAT
   is an attribute where GPGME_ATTR_EXPIRE is probably the most useful
   one.  WHATIDX is to be passed as 0 for most attributes . */
unsigned long gpgme_get_sig_ulong_attr (gpgme_ctx_t ctx, int idx,
                                        _gpgme_attr_t what, int whatidx)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return 0;

  switch (what)
    {
    case GPGME_ATTR_CREATED:
      return sig->timestamp;

    case GPGME_ATTR_EXPIRE:
      return sig->exp_timestamp;

    case GPGME_ATTR_VALIDITY:
      return (unsigned long) sig->validity;

    case GPGME_ATTR_SIG_STATUS:
      switch (gpg_err_code (sig->status))
	{
	case GPG_ERR_NO_ERROR:
	  return GPGME_SIG_STAT_GOOD;
	  
	case GPG_ERR_BAD_SIGNATURE:
	  return GPGME_SIG_STAT_BAD;
	  
	case GPG_ERR_NO_PUBKEY:
	  return GPGME_SIG_STAT_NOKEY;
	  
	case GPG_ERR_NO_DATA:
	  return GPGME_SIG_STAT_NOSIG;
	  
	case GPG_ERR_SIG_EXPIRED:
	  return GPGME_SIG_STAT_GOOD_EXP;
	  
	case GPG_ERR_KEY_EXPIRED:
	  return GPGME_SIG_STAT_GOOD_EXPKEY;
	  
	default:
	  return GPGME_SIG_STAT_ERROR;
	}

    case GPGME_ATTR_SIG_SUMMARY:
      return sig->summary;

    default:
      break;
    }
  return 0;
}


const char *gpgme_get_sig_string_attr (gpgme_ctx_t ctx, int idx,
                                      _gpgme_attr_t what, int whatidx)
{
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  result = gpgme_op_verify_result (ctx);
  sig = result->signatures;

  while (sig && idx)
    {
      sig = sig->next;
      idx--;
    }
  if (!sig || idx)
    return NULL;

  switch (what)
    {
    case GPGME_ATTR_FPR:
      return sig->fpr;

    case GPGME_ATTR_ERRTOK:
      if (whatidx == 1)
        return sig->wrong_key_usage ? "Wrong_Key_Usage" : "";
      else
	return "";
    default:
      break;
    }

  return NULL;
}

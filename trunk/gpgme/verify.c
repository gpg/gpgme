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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "key.h"


struct verify_result
{
  GpgmeSigStat status;
  GpgmeSigStat expstatus;	/* Only used by finish_sig.  */
  GpgmeData notation;		/* We store an XML fragment here.  */
  int collecting;		/* Private to finish_sig().  */
  int notation_in_data;		/* Private to add_notation().  */
  char fpr[41];			/* Fingerprint of a good signature or keyid of
				   a bad one.  */
  ulong timestamp;		/* Signature creation time.  */
  ulong exptimestamp;		/* Signature exipration time or 0.  */
  GpgmeValidity validity;
  int wrong_key_usage;  
  char trust_errtok[31];	/* Error token send with the trust status.  */
};
typedef struct verify_result *VerifyResult;


static void
release_verify_result (void *hook)
{
  VerifyResult result = (VerifyResult) hook;

  gpgme_data_release (result->notation);
}


/* Check whether STRING starts with TOKEN and return true in this
   case.  This is case insensitive.  If NEXT is not NULL return the
   number of bytes to be added to STRING to get to the next token; a
   returned value of 0 indicates end of line.  */
static int 
is_token (const char *string, const char *token, size_t *next)
{
  size_t n = 0;

  for (;*string && *token && *string == *token; string++, token++, n++)
    ;
  if (*token || (*string != ' ' && !*string))
    return 0;
  if (next)
    {
      for (; *string == ' '; string++, n++)
        ;
      *next = n;
    }
  return 1;
}

static int
skip_token (const char *string, size_t *next)
{
  size_t n = 0;

  for (;*string && *string != ' '; string++, n++)
    ;
  for (;*string == ' '; string++, n++)
    ;
  if (!*string)
    return 0;
  if (next)
    *next = n;
  return 1;
}


static size_t
copy_token (const char *string, char *buffer, size_t length)
{
  const char *s = string;
  char *p = buffer;
  size_t i;

  for (i = 1; i < length && *s && *s != ' ' ; i++)
    *p++ = *s++;
  *p = 0;
  /* continue scanning in case the copy was truncated */
  while (*s && *s != ' ')
    s++;
  return s - string;
}


/* FIXME: Check that we are adding this to the correct signature.  */
static GpgmeError
add_notation (VerifyResult result, GpgmeStatusCode code, const char *notation)
{
  GpgmeData dh = result->notation;

  if (!dh)
    {
      if (gpgme_data_new (&dh))
	return GPGME_Out_Of_Core;
      result->notation = dh;
      _gpgme_data_append_string (dh, "  <notation>\n");
    }

  if (code == GPGME_STATUS_NOTATION_DATA)
    {
      if (!result->notation_in_data)
	_gpgme_data_append_string (dh, "  <data>");
      _gpgme_data_append_percentstring_for_xml (dh, notation);
      result->notation_in_data = 1;
      return 0;
    }

  if (result->notation_in_data)
    {
      _gpgme_data_append_string (dh, "</data>\n");
      result->notation_in_data = 0;
    }

  if (code == GPGME_STATUS_NOTATION_NAME)
    {
      _gpgme_data_append_string (dh, "  <name>");
      _gpgme_data_append_percentstring_for_xml (dh, notation);
      _gpgme_data_append_string (dh, "</name>\n");
    }
  else if (code == GPGME_STATUS_POLICY_URL)
    {
      _gpgme_data_append_string (dh, "  <policy>");
      _gpgme_data_append_percentstring_for_xml (dh, notation);
      _gpgme_data_append_string (dh, "</policy>\n");
    }
  else
    assert (0);
  return 0;
}


/* Finish a pending signature info collection.  */
static void
finish_sig (VerifyResult result)
{
  struct ctx_op_data *op_data;

  /* We intimately know that gpgme_op_data_lookup appends the data to
     the op_data structure.  We can use this here to change the type
     knowing only the hook value.  */
  op_data = (struct ctx_op_data *) ((void *) result
				    - sizeof (struct ctx_op_data));
  op_data->type = OPDATA_VERIFY;
}


GpgmeError
_gpgme_verify_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  VerifyResult result;
  GpgmeError err;
  char *p;
  size_t n;
  int i;

  err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY_COLLECTING, (void **) &result,
			       -1, NULL);
  if (err)
    return err;

  if (code == GPGME_STATUS_GOODSIG || code == GPGME_STATUS_EXPSIG
      || code == GPGME_STATUS_EXPKEYSIG || code == GPGME_STATUS_BADSIG
      || code == GPGME_STATUS_ERRSIG)
    {
      /* A new signature starts.  */
      if (result)
	finish_sig (result);
      err = _gpgme_op_data_lookup (ctx, OPDATA_VERIFY_COLLECTING, (void **) &result,
				   sizeof (*result), release_verify_result);
      if (err)
	return err;
    }

  switch (code)
    {
    case GPGME_STATUS_NODATA:
    case GPGME_STATUS_UNEXPECTED:
      if (!result)
	return GPGME_General_Error;
      result->status = GPGME_SIG_STAT_NOSIG;
      break;

    case GPGME_STATUS_GOODSIG:
      if (!result)
	return GPGME_General_Error;
      result->expstatus = GPGME_SIG_STAT_GOOD;
      break;

    case GPGME_STATUS_EXPSIG:
      if (!result)
	return GPGME_General_Error;
      result->expstatus = GPGME_SIG_STAT_GOOD_EXP;
      break;

    case GPGME_STATUS_EXPKEYSIG:
      if (!result)
	return GPGME_General_Error;
      result->expstatus = GPGME_SIG_STAT_GOOD_EXPKEY;
      break;

    case GPGME_STATUS_VALIDSIG:
      if (!result)
	return GPGME_General_Error;
      result->status = GPGME_SIG_STAT_GOOD;
      i = copy_token (args, result->fpr, DIM (result->fpr));
      /* Skip the formatted date.  */
      while (args[i] && args[i] == ' ')
	i++;
      while (args[i] && args[i] != ' ')
	i++;
      /* And get the timestamp.  */
      result->timestamp = strtoul (args + i, &p, 10);
      if (args[i])
        result->exptimestamp = strtoul (p, NULL, 10);
      break;

    case GPGME_STATUS_BADSIG:
      if (!result)
	return GPGME_General_Error;
      result->status = GPGME_SIG_STAT_BAD;
      /* Store the keyID in the fpr field.  */
      copy_token (args, result->fpr, DIM (result->fpr));
      break;

    case GPGME_STATUS_ERRSIG:
      if (!result)
	return GPGME_General_Error;
      /* The return code is the 6th argument, if it is 9, the problem
	 is a missing key.  Note that this is not emitted by gpgsm */
      for (p = args, i = 0; p && *p && i < 5; i++)
        {
          p = strchr (p, ' ');
          if (p)
            while (*p == ' ')
              p++;
        }
      if (p && *(p++) == '9' && (*p == '\0' || *p == ' '))
	result->status = GPGME_SIG_STAT_NOKEY;
      else
	result->status = GPGME_SIG_STAT_ERROR;
      /* Store the keyID in the fpr field.  */
      copy_token (args, result->fpr, DIM (result->fpr));
      break;

    case GPGME_STATUS_NOTATION_NAME:
    case GPGME_STATUS_NOTATION_DATA:
    case GPGME_STATUS_POLICY_URL:
      if (!result)
	return GPGME_General_Error;
      err = add_notation (result, code, args);
      if (err)
	return err;
      break;

    case GPGME_STATUS_TRUST_UNDEFINED:
      if (!result)
	return GPGME_General_Error;
      result->validity = GPGME_VALIDITY_UNKNOWN;
      copy_token (args, result->trust_errtok,
                  DIM(result->trust_errtok));
      break;
    case GPGME_STATUS_TRUST_NEVER:
      if (!result)
	return GPGME_General_Error;
      result->validity = GPGME_VALIDITY_NEVER;
      copy_token (args, result->trust_errtok,
                  DIM(result->trust_errtok));
      break;
    case GPGME_STATUS_TRUST_MARGINAL:
      if (!result)
	return GPGME_General_Error;
      if (result->status == GPGME_SIG_STAT_GOOD)
        result->validity = GPGME_VALIDITY_MARGINAL;
      copy_token (args, result->trust_errtok,
                  DIM(result->trust_errtok));
      break;
    case GPGME_STATUS_TRUST_FULLY:
    case GPGME_STATUS_TRUST_ULTIMATE:
      if (!result)
	return GPGME_General_Error;
      if (result->status == GPGME_SIG_STAT_GOOD)
        result->validity = GPGME_VALIDITY_FULL;
      break;

    case GPGME_STATUS_END_STREAM:
      break;

    case GPGME_STATUS_ERROR:
      if (!result)
	return GPGME_General_Error;
      /* Generic error, we need this for gpgsm (and maybe for gpg in future)
         to get error descriptions. */
      if (is_token (args, "verify.findkey", &n) && n)
        {
          args += n;
          if (is_token (args, "No_Public_Key", NULL))
            result->status = GPGME_SIG_STAT_NOKEY;
          else
            result->status = GPGME_SIG_STAT_ERROR;

        }
      else if (skip_token (args, &n) && n)
        {
          args += n;
          if (is_token (args, "Wrong_Key_Usage", NULL))
            result->wrong_key_usage = 1;
        }
      break;

    case GPGME_STATUS_EOF:
      if (result)
	{
	  finish_sig (result);

	  /* FIXME: Put all notation data into one XML fragment.  */
	  if (result->notation)
	    {
	      GpgmeData dh = result->notation;
	      
	      if (result->notation_in_data)
		{
		  _gpgme_data_append_string (dh, "</data>\n");
		  result->notation_in_data = 0;
		}
	      _gpgme_data_append_string (dh, "</notation>\n");
	      ctx->notation = dh;
	      result->notation = NULL;
	    }
	}
      break;
 
    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


static GpgmeError
_gpgme_op_verify_start (GpgmeCtx ctx, int synchronous,
			GpgmeData sig, GpgmeData signed_text, GpgmeData plaintext)
{
  int err = 0;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, _gpgme_verify_status_handler,
				    ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  /* Check the supplied data.  */
  if (!sig)
    {
      err = GPGME_No_Data;
      goto leave;
    }
  if (!signed_text && !plaintext)
    {
      err = GPGME_Invalid_Value;
      goto leave;
    }
  err = _gpgme_engine_op_verify (ctx->engine, sig, signed_text, plaintext);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


GpgmeError
gpgme_op_verify_start (GpgmeCtx ctx, GpgmeData sig, GpgmeData signed_text,
		       GpgmeData plaintext)
{
  return _gpgme_op_verify_start (ctx, 0, sig, signed_text, plaintext);
}


/**
 * gpgme_op_verify:
 * @c: the context
 * @sig: the signature data
 * @text: the signed text
 * 
 * Perform a signature check on the signature given in @sig.  If @text
 * is a new and uninitialized data object, it is assumed that @sig
 * contains a normal or cleartext signature, and the plaintext is
 * returned in @text upon successful verification.
 *
 * If @text is initialized, it is assumed that @sig is a detached
 * signature for the material given in @text.
 *
 * Return value: 0 on success or an errorcode if something not related to
 *               the signature itself did go wrong.
 **/
GpgmeError
gpgme_op_verify (GpgmeCtx ctx, GpgmeData sig, GpgmeData signed_text,
		 GpgmeData plaintext)
{
  GpgmeError err;

  gpgme_data_release (ctx->notation);
  ctx->notation = NULL;
    
  err = _gpgme_op_verify_start (ctx, 1, sig, signed_text, plaintext);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}


/**
 * gpgme_get_sig_status:
 * @c: Context
 * @idx: Index of the signature starting at 0
 * @r_stat: Returns the status
 * @r_created: Returns the creation timestamp
 * 
 * Return information about an already verified signatures. 
 *
 * The result of this operation is returned in @r_stat which can take these
 * values:
 *  GPGME_SIG_STAT_NONE:  No status - should not happen
 *  GPGME_SIG_STAT_GOOD:  The signature is valid 
 *  GPGME_SIG_STAT_BAD:   The signature is not valid
 *  GPGME_SIG_STAT_NOKEY: The signature could not be checked due to a
 *                        missing key
 *  GPGME_SIG_STAT_NOSIG: This is not a signature
 *  GPGME_SIG_STAT_ERROR: Due to some other error the check could not be done.
 *  GPGME_SIG_STAT_DIFF:  There is more than 1 signature and they have not
 *                        the same status.
 *  GPGME_SIG_STAT_GOOD_EXP:  The signature is good but has expired.
 *  GPGME_SIG_STAT_GOOD_KEYEXP:  The signature is good but the key has expired.
 *
 * 
 * Return value: The fingerprint or NULL in case of an problem or
 *               when there are no more signatures.
 **/
const char *
gpgme_get_sig_status (GpgmeCtx ctx, int idx,
                      GpgmeSigStat *r_stat, time_t *r_created)
{
  struct ctx_op_data *op_data;
  VerifyResult result;

  if (!ctx || ctx->pending)
    return NULL;	/* No results yet or verification error.  */

  op_data = ctx->op_data;
  while (op_data)
    {
      while (op_data && op_data->type != OPDATA_VERIFY)
	op_data = op_data->next;
      if (idx-- == 0)
	break;
      op_data = op_data->next;	
    }
  if (!op_data)
    return NULL;	/* No more signatures.  */

  result = (VerifyResult) op_data->hook;
  if (r_stat)
    *r_stat = result->status;
  if (r_created)
    *r_created = result->timestamp;
  return result->fpr;
}


/* Build a summary vector from RESULT. */
static unsigned long
calc_sig_summary (VerifyResult result)
{
  unsigned long sum = 0;

  if (result->validity == GPGME_VALIDITY_FULL
     || result->validity == GPGME_VALIDITY_ULTIMATE)
    {
      if (result->status == GPGME_SIG_STAT_GOOD
          || result->status == GPGME_SIG_STAT_GOOD_EXP
          || result->status == GPGME_SIG_STAT_GOOD_EXPKEY)
        sum |= GPGME_SIGSUM_GREEN;
    }
  else if (result->validity == GPGME_VALIDITY_NEVER)
    {
      if (result->status == GPGME_SIG_STAT_GOOD
          || result->status == GPGME_SIG_STAT_GOOD_EXP
          || result->status == GPGME_SIG_STAT_GOOD_EXPKEY)
        sum |= GPGME_SIGSUM_RED;
    }
  else if (result->status == GPGME_SIG_STAT_BAD)
    sum |= GPGME_SIGSUM_RED;

  /* fixme: handle the case when key and message are expired. */
  if (result->status == GPGME_SIG_STAT_GOOD_EXP)
    sum |= GPGME_SIGSUM_SIG_EXPIRED;
  else if (result->status == GPGME_SIG_STAT_GOOD_EXPKEY)
    sum |= GPGME_SIGSUM_KEY_EXPIRED;
  else if (result->status == GPGME_SIG_STAT_NOKEY)
    sum |= GPGME_SIGSUM_KEY_MISSING;
  else if (result->status == GPGME_SIG_STAT_ERROR)
    sum |= GPGME_SIGSUM_SYS_ERROR;

  if ( !strcmp (result->trust_errtok, "Certificate_Revoked"))
    sum |= GPGME_SIGSUM_KEY_REVOKED;
  else if ( !strcmp (result->trust_errtok, "No_CRL_Known"))
    sum |= GPGME_SIGSUM_CRL_MISSING;
  else if ( !strcmp (result->trust_errtok, "CRL_Too_Old"))
    sum |= GPGME_SIGSUM_CRL_TOO_OLD;
  else if ( !strcmp (result->trust_errtok, "No_Policy_Match"))
    sum |= GPGME_SIGSUM_BAD_POLICY;
  else if (*result->trust_errtok)
    sum |= GPGME_SIGSUM_SYS_ERROR;

  if (result->wrong_key_usage)
    sum |= GPGME_SIGSUM_BAD_POLICY;

  /* Set the valid flag when the signature is unquestionable
     valid. */
  if ((sum & GPGME_SIGSUM_GREEN) && !(sum & ~GPGME_SIGSUM_GREEN))
    sum |= GPGME_SIGSUM_VALID;

  return sum;
}


const char *
gpgme_get_sig_string_attr (GpgmeCtx ctx, int idx, GpgmeAttr what, int whatidx)
{
  struct ctx_op_data *op_data;
  VerifyResult result;

  if (!ctx || ctx->pending)
    return NULL;	/* No results yet or verification error.  */

  op_data = ctx->op_data;
  while (op_data)
    {
      while (op_data && op_data->type != OPDATA_VERIFY)
	op_data = op_data->next;
      if (idx-- == 0)
	break;
      op_data = op_data->next;	
    }
  if (!op_data)
    return NULL;	/* No more signatures.  */

  result = (VerifyResult) op_data->hook;
  switch (what)
    {
    case GPGME_ATTR_FPR:
      return result->fpr;
    case GPGME_ATTR_ERRTOK:
      if (whatidx == 1)
        return result->wrong_key_usage? "Wrong_Key_Usage":"";
      else
        return result->trust_errtok;
    default:
      break;
    }
  return NULL;
}


unsigned long
gpgme_get_sig_ulong_attr (GpgmeCtx ctx, int idx, GpgmeAttr what, int reserved)
{
  struct ctx_op_data *op_data;
  VerifyResult result;

  if (!ctx || ctx->pending)
    return 0;	/* No results yet or verification error.  */

  op_data = ctx->op_data;
  while (op_data)
    {
      while (op_data && op_data->type != OPDATA_VERIFY)
	op_data = op_data->next;
      if (idx-- == 0)
	break;
      op_data = op_data->next;	
    }
  if (!op_data)
    return 0;	/* No more signatures.  */

  result = (VerifyResult) op_data->hook;
  switch (what)
    {
    case GPGME_ATTR_CREATED:
      return result->timestamp;
    case GPGME_ATTR_EXPIRE:
      return result->exptimestamp;
    case GPGME_ATTR_VALIDITY:
      return (unsigned long) result->validity;
    case GPGME_ATTR_SIG_STATUS:
      return (unsigned long) result->status;
    case GPGME_ATTR_SIG_SUMMARY:
      return calc_sig_summary (result);
    default:
      break;
    }
  return 0;
}


/**
 * gpgme_get_sig_key:
 * @c: context
 * @idx: Index of the signature starting at 0
 * @r_key: Returns the key object
 * 
 * Return a key object which was used to check the signature. 
 * 
 * Return value: An Errorcode or 0 for success. GPGME_EOF is returned to
 *               indicate that there are no more signatures. 
 **/
GpgmeError
gpgme_get_sig_key (GpgmeCtx ctx, int idx, GpgmeKey *r_key)
{
  struct ctx_op_data *op_data;
  VerifyResult result;

  if (!ctx || !r_key)
    return GPGME_Invalid_Value;

  if (ctx->pending)
    return GPGME_Busy;

  op_data = ctx->op_data;
  while (op_data)
    {
      while (op_data && op_data->type != OPDATA_VERIFY)
	op_data = op_data->next;
      if (idx-- == 0)
	break;
      op_data = op_data->next;	
    }
  if (!op_data)
    return GPGME_EOF;

  result = (VerifyResult) op_data->hook;

  return gpgme_get_key (ctx, result->fpr, r_key, 0, 0);
}

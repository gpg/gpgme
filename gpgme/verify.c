/* verify.c -  signature verification
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "key.h"


struct verify_result_s
{
  struct verify_result_s *next;
  GpgmeSigStat status;
  GpgmeSigStat expstatus; /* only used by finish_sig */
  GpgmeData notation;	/* We store an XML fragment here.  */
  int collecting;	/* Private to finish_sig().  */
  int notation_in_data;	/* Private to add_notation().  */
  char fpr[41];		/* Fingerprint of a good signature or keyid of
			   a bad one.  */
  ulong timestamp;	/* Signature creation time.  */
  ulong exptimestamp;   /* signature exipration time or 0 */
  GpgmeValidity validity;
  char trust_errtok[31]; /* error token send with the trust status */
};


void
_gpgme_release_verify_result (VerifyResult result)
{
  while (result)
    {
      VerifyResult next_result = result->next;
      gpgme_data_release (result->notation);
      xfree (result);
      result = next_result;
    }
}

/* Check whether STRING starts with TOKEN and return true in this
   case.  This is case insensitive.  If NEXT is not NULL return the
   number of bytes to be added to STRING to get to the next token; a
   returned value of 0 indicates end of line. */
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
static void
add_notation (GpgmeCtx ctx, GpgStatusCode code, const char *data)
{
  GpgmeData dh = ctx->result.verify->notation;

  if (!dh)
    {
      if (gpgme_data_new (&dh))
	{
	  ctx->error = mk_error (Out_Of_Core);
	  return;
        }
      ctx->result.verify->notation = dh;
      _gpgme_data_append_string (dh, "  <notation>\n");
    }

  if (code == STATUS_NOTATION_DATA)
    {
      if (!ctx->result.verify->notation_in_data)
	_gpgme_data_append_string (dh, "  <data>");
      _gpgme_data_append_percentstring_for_xml (dh, data);
      ctx->result.verify->notation_in_data = 1;
      return;
    }

  if (ctx->result.verify->notation_in_data)
    {
      _gpgme_data_append_string (dh, "</data>\n");
      ctx->result.verify->notation_in_data = 0;
    }

  if (code == STATUS_NOTATION_NAME)
    {
      _gpgme_data_append_string (dh, "  <name>");
      _gpgme_data_append_percentstring_for_xml (dh, data);
      _gpgme_data_append_string (dh, "</name>\n");
    }
  else if (code == STATUS_POLICY_URL)
    {
      _gpgme_data_append_string (dh, "  <policy>");
      _gpgme_data_append_percentstring_for_xml (dh, data);
      _gpgme_data_append_string (dh, "</policy>\n");
    }
  else
    assert (0);
}


/* 
 * finish a pending signature info collection and prepare for a new
 * signature info collection
 */
static void
finish_sig (GpgmeCtx ctx, int stop)
{
  if (ctx->result.verify->status == GPGME_SIG_STAT_GOOD)
    ctx->result.verify->status = ctx->result.verify->expstatus;

  if (stop)
    return; /* nothing to do */

  if (ctx->result.verify->collecting)
    {
      VerifyResult res2;

      ctx->result.verify->collecting = 0;
      /* Create a new result structure.  */
      res2 = xtrycalloc (1, sizeof *res2);
      if (!res2)
	{
	  ctx->error = mk_error (Out_Of_Core);
	  return;
        }

      res2->next = ctx->result.verify;
      ctx->result.verify = res2;
    }
    
  ctx->result.verify->collecting = 1;
}


void
_gpgme_verify_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  char *p;
  size_t n;
  int i;

  if (ctx->error)
    return;
  test_and_allocate_result (ctx, verify);

  if (code == STATUS_GOODSIG
      || code == STATUS_EXPSIG
      || code == STATUS_EXPKEYSIG
      || code == STATUS_BADSIG
      || code == STATUS_ERRSIG)
    {
      finish_sig (ctx,0);
      if (ctx->error)
	return;
    }

  switch (code)
    {
    case STATUS_NODATA:
      ctx->result.verify->status = GPGME_SIG_STAT_NOSIG;
      break;

    case STATUS_GOODSIG:
      ctx->result.verify->expstatus = GPGME_SIG_STAT_GOOD;
      break;
    
    case STATUS_EXPSIG:
      ctx->result.verify->expstatus = GPGME_SIG_STAT_GOOD_EXP;
      break;

    case STATUS_EXPKEYSIG:
      ctx->result.verify->expstatus = GPGME_SIG_STAT_GOOD_EXPKEY;
      break;

    case STATUS_VALIDSIG:
      ctx->result.verify->status = GPGME_SIG_STAT_GOOD;
      i = copy_token (args, ctx->result.verify->fpr,
                      DIM(ctx->result.verify->fpr));
      /* Skip the formatted date.  */
      while (args[i] && args[i] == ' ')
	i++;
      while (args[i] && args[i] != ' ')
	i++;
      /* And get the timestamp.  */
      ctx->result.verify->timestamp = strtoul (args+i, &p, 10);
      if (args[i])
        ctx->result.verify->exptimestamp = strtoul (p, NULL, 10);
      break;

    case STATUS_BADSIG:
      ctx->result.verify->status = GPGME_SIG_STAT_BAD;
      /* Store the keyID in the fpr field.  */
      copy_token (args, ctx->result.verify->fpr,
                  DIM(ctx->result.verify->fpr));
      break;

    case STATUS_ERRSIG:
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
	ctx->result.verify->status = GPGME_SIG_STAT_NOKEY;
      else
	ctx->result.verify->status = GPGME_SIG_STAT_ERROR;
      /* Store the keyID in the fpr field.  */
      copy_token (args, ctx->result.verify->fpr,
                  DIM(ctx->result.verify->fpr));
      break;

    case STATUS_NOTATION_NAME:
    case STATUS_NOTATION_DATA:
    case STATUS_POLICY_URL:
      add_notation (ctx, code, args);
      break;

    case STATUS_TRUST_UNDEFINED:
      ctx->result.verify->validity = GPGME_VALIDITY_UNKNOWN;
      copy_token (args, ctx->result.verify->trust_errtok,
                  DIM(ctx->result.verify->trust_errtok));
      break;
    case STATUS_TRUST_NEVER:
      ctx->result.verify->validity = GPGME_VALIDITY_NEVER;
      copy_token (args, ctx->result.verify->trust_errtok,
                  DIM(ctx->result.verify->trust_errtok));
      break;
    case STATUS_TRUST_MARGINAL:
      if (ctx->result.verify->status == GPGME_SIG_STAT_GOOD)
        ctx->result.verify->validity = GPGME_VALIDITY_MARGINAL;
      copy_token (args, ctx->result.verify->trust_errtok,
                  DIM(ctx->result.verify->trust_errtok));
      break;
    case STATUS_TRUST_FULLY:
    case STATUS_TRUST_ULTIMATE:
      if (ctx->result.verify->status == GPGME_SIG_STAT_GOOD)
        ctx->result.verify->validity = GPGME_VALIDITY_FULL;
      break;

    case STATUS_END_STREAM:
      break;

    case STATUS_ERROR:
      /* Generic error, we need this for gpgsm (and maybe for gpg in future)
         to get error descriptions. */
      if (is_token (args, "verify.findkey", &n) && n)
        {
          args += n;
          if (is_token (args, "No_Public_Key", NULL))
            ctx->result.verify->status = GPGME_SIG_STAT_NOKEY;
          else
            ctx->result.verify->status = GPGME_SIG_STAT_ERROR;

        }
      break;

    case STATUS_EOF:
      finish_sig (ctx,1);

      /* FIXME: Put all notation data into one XML fragment.  */
      if (ctx->result.verify->notation)
	{
	  GpgmeData dh = ctx->result.verify->notation;

	  if (ctx->result.verify->notation_in_data)
	    {
	      _gpgme_data_append_string (dh, "</data>\n");
	      ctx->result.verify->notation_in_data = 0;
	    }
	  _gpgme_data_append_string (dh, "</notation>\n");
	  ctx->notation = dh;
	  ctx->result.verify->notation = NULL;
	}
      break;
 
    default:
      /* Ignore all other codes.  */
      break;
    }
}

static GpgmeError
_gpgme_op_verify_start (GpgmeCtx ctx, int synchronous,
			GpgmeData sig, GpgmeData text)
{
  int err = 0;
  int pipemode = 0;	 /* !!text; use pipemode for detached sigs.  */

  if (!pipemode)
    ;	/* XXX I am not sure what should happen/not happen in
	   pipemode.  */

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

#if 0	/* FIXME */
  if (pipemode)
    _gpgme_gpg_enable_pipemode (c->engine->engine.gpg);
#endif

  _gpgme_engine_set_status_handler (ctx->engine, _gpgme_verify_status_handler,
				    ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  /* Check the supplied data.  */
  if (gpgme_data_get_type (sig) == GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (No_Data);
      goto leave;
    }
  if (!text)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
  _gpgme_data_set_mode (sig, GPGME_DATA_MODE_OUT);
  if (gpgme_data_get_type (text) == GPGME_DATA_TYPE_NONE)
    /* Normal or cleartext signature.  */
    _gpgme_data_set_mode (text, GPGME_DATA_MODE_IN);
  else
    /* Detached signature.  */
    _gpgme_data_set_mode (text, GPGME_DATA_MODE_OUT);

  err = _gpgme_engine_op_verify (ctx->engine, sig, text);
  if (!err)	/* And kick off the process.  */
    err = _gpgme_engine_start (ctx->engine, ctx);

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
gpgme_op_verify_start (GpgmeCtx ctx, GpgmeData sig, GpgmeData text)
{
  return _gpgme_op_verify_start (ctx, 0, sig, text);
}

/* 
 * Figure out a common status value for all signatures 
 */
GpgmeSigStat
_gpgme_intersect_stati (VerifyResult result)
{
  GpgmeSigStat status = result->status;

  for (result = result->next; result; result = result->next)
    {
      if (status != result->status) 
	return GPGME_SIG_STAT_DIFF;
    }
  return status;
}

/**
 * gpgme_op_verify:
 * @c: the context
 * @sig: the signature data
 * @text: the signed text
 * @r_stat: returns the status of the signature
 * 
 * Perform a signature check on the signature given in @sig.  If @text
 * is a new and uninitialized data object, it is assumed that @sig
 * contains a normal or cleartext signature, and the plaintext is
 * returned in @text upon successful verification.
 *
 * If @text is initialized, it is assumed that @sig is a detached
 * signature for the material given in @text.
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
 * Return value: 0 on success or an errorcode if something not related to
 *               the signature itself did go wrong.
 **/
GpgmeError
gpgme_op_verify (GpgmeCtx ctx, GpgmeData sig, GpgmeData text,
		 GpgmeSigStat *r_stat)
{
  GpgmeError err;

  if (!r_stat)
    return mk_error (Invalid_Value);

  gpgme_data_release (ctx->notation);
  ctx->notation = NULL;
    
  *r_stat = GPGME_SIG_STAT_NONE;
  err = _gpgme_op_verify_start (ctx, 1, sig, text);
  if (!err)
    {
      err = _gpgme_wait_one (ctx);
      if (!err && ctx->result.verify)
	*r_stat = _gpgme_intersect_stati (ctx->result.verify);
    }
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
 * Return value: The fingerprint or NULL in case of an problem or
 *               when there are no more signatures.
 **/
const char *
gpgme_get_sig_status (GpgmeCtx c, int idx,
                      GpgmeSigStat *r_stat, time_t *r_created)
{
  VerifyResult result;

  if (!c || c->pending || !c->result.verify)
    return NULL;	/* No results yet or verification error.  */

  for (result = c->result.verify;
       result && idx > 0; result = result->next, idx--)
    ;
  if (!result)
    return NULL;	/* No more signatures.  */

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

  /* Set the valid flag when the signature is unquestionable
     valid. */
  if ((sum & GPGME_SIGSUM_GREEN) && !(sum & ~GPGME_SIGSUM_GREEN))
    sum |= GPGME_SIGSUM_VALID;

  return sum;
}


const char *
gpgme_get_sig_string_attr (GpgmeCtx c, int idx, GpgmeAttr what, int reserved)
{
  VerifyResult result;

  if (!c || c->pending || !c->result.verify)
    return NULL;	/* No results yet or verification error.  */
  if (reserved)
    return NULL; /* We might want to use it to enumerate attributes of
                    one signature */
  for (result = c->result.verify;
       result && idx > 0; result = result->next, idx--)
    ;
  if (!result)
    return NULL;	/* No more signatures.  */

  switch (what)
    {
    case GPGME_ATTR_FPR:
      return result->fpr;
    case GPGME_ATTR_ERRTOK:
      return result->trust_errtok;
    default:
      break;
    }
  return NULL;
}

unsigned long
gpgme_get_sig_ulong_attr (GpgmeCtx c, int idx, GpgmeAttr what, int reserved)
{
  VerifyResult result;

  if (!c || c->pending || !c->result.verify)
    return 0;	/* No results yet or verification error.  */
  if (reserved)
    return 0; 
  for (result = c->result.verify;
       result && idx > 0; result = result->next, idx--)
    ;
  if (!result)
    return 0;	/* No more signatures.  */

  switch (what)
    {
    case GPGME_ATTR_CREATED:
      return result->timestamp;
    case GPGME_ATTR_EXPIRE:
      return result->exptimestamp;
    case GPGME_ATTR_VALIDITY:
      return (unsigned long)result->validity;
    case GPGME_ATTR_SIG_STATUS:
      return (unsigned long)result->status;
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
gpgme_get_sig_key (GpgmeCtx c, int idx, GpgmeKey *r_key)
{
  VerifyResult result;
  GpgmeError err = 0;

  if (!c || !r_key)
    return mk_error (Invalid_Value);
  if (c->pending || !c->result.verify)
    return mk_error (Busy);
  
  for (result = c->result.verify;
       result && idx > 0; result = result->next, idx--)
    ;
  if (!result)
    return mk_error (EOF);
  
  if (strlen(result->fpr) < 16)	/* We have at least a key ID.  */
    return mk_error (Invalid_Key);
  
  *r_key = _gpgme_key_cache_get (result->fpr);
  if (!*r_key)
    {
      GpgmeCtx listctx;
      
      /* Fixme: This can be optimized by keeping an internal context
	 used for such key listings.  */
      err = gpgme_new (&listctx);
      if (err)
	return err;
      gpgme_set_protocol (listctx, gpgme_get_protocol (c));
      gpgme_set_keylist_mode (listctx, c->keylist_mode);
      err = gpgme_op_keylist_start (listctx, result->fpr, 0);
      if (!err)
	err = gpgme_op_keylist_next (listctx, r_key);
      gpgme_release (listctx);
    }
  return err;
}


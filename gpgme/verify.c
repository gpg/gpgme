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
  GpgmeData notation;	/* We store an XML fragment here.  */
  int collecting;	/* Private to finish_sig().  */
  int notation_in_data;	/* Private to add_notation().  */
  char fpr[41];		/* Fingerprint of a good signature or keyid of
			   a bad one.  */
  ulong timestamp;	/* Signature creation time.  */
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
  int i;

  if (ctx->error)
    return;
  test_and_allocate_result (ctx, verify);

  if (code == STATUS_GOODSIG || code == STATUS_BADSIG || code == STATUS_ERRSIG)
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
      /* We only look at VALIDSIG */
      break;

    case STATUS_VALIDSIG:
      ctx->result.verify->status = GPGME_SIG_STAT_GOOD;
      p = ctx->result.verify->fpr;
      for (i = 0; i < DIM(ctx->result.verify->fpr)
	     && args[i] && args[i] != ' ' ; i++)
	*p++ = args[i];
      *p = 0;
      /* Skip the formatted date.  */
      while (args[i] && args[i] == ' ')
	i++;
      while (args[i] && args[i] != ' ')
	i++;
      /* And get the timestamp.  */
      ctx->result.verify->timestamp = strtoul (args+i, NULL, 10);
      break;

    case STATUS_BADSIG:
      ctx->result.verify->status = GPGME_SIG_STAT_BAD;
      /* Store the keyID in the fpr field.  */
      p = ctx->result.verify->fpr;
      for (i = 0; i < DIM(ctx->result.verify->fpr)
	     && args[i] && args[i] != ' ' ; i++)
	*p++ = args[i];
      *p = 0;
      break;

    case STATUS_ERRSIG:
      /* The return code is the 6th argument, if it is 9, the problem
	 is a missing key.  */
      for (p = args, i = 0; p && i < 5; i++)
	p = strchr (p, ' ');
      if (p && *(++p) == '9' && *(++p) == '\0')
	ctx->result.verify->status = GPGME_SIG_STAT_NOKEY;
      else
	ctx->result.verify->status = GPGME_SIG_STAT_ERROR;
      /* Store the keyID in the fpr field.  */
      p = ctx->result.verify->fpr;
      for (i = 0; i < DIM(ctx->result.verify->fpr)
	     && args[i] && args[i] != ' ' ; i++)
	*p++ = args[i];
      *p = 0;
      break;

    case STATUS_NOTATION_NAME:
    case STATUS_NOTATION_DATA:
    case STATUS_POLICY_URL:
      add_notation (ctx, code, args);
      break;

    case STATUS_END_STREAM:
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

GpgmeError
gpgme_op_verify_start (GpgmeCtx ctx, GpgmeData sig, GpgmeData text)
{
  int err = 0;
  int pipemode = 0;	 /* !!text; use pipemode for detached sigs.  */

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_release_result (ctx);
    
  if (!pipemode)
    {
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }

  if (!ctx->engine)
    err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			     : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
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
  if (text && gpgme_data_get_type (text) == GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (No_Data);
      goto leave;
    }
  _gpgme_data_set_mode (sig, GPGME_DATA_MODE_OUT);
  if (text)	    /* Detached signature.  */
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
 * Perform a signature check on the signature given in @sig. Currently it is
 * assumed that this is a detached signature for the material given in @text.
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
  err = gpgme_op_verify_start (ctx, sig, text);
  if (!err)
    {
      gpgme_wait (ctx, &err, 1);
      if (!err)
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
      gpgme_set_keylist_mode (listctx, c->keylist_mode);
      err = gpgme_op_keylist_start (listctx, result->fpr, 0);
      if (!err)
	err = gpgme_op_keylist_next (listctx, r_key);
      gpgme_release (listctx);
    }
  return err;
}

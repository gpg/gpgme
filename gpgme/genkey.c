/* genkey.c -  key generation
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


struct genkey_result_s
{
  int created_primary : 1;
  int created_sub : 1;
};


void
_gpgme_release_genkey_result (GenKeyResult result)
{
  if (!result)
    return;
  xfree (result);
}

static void
genkey_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  _gpgme_progress_status_handler (ctx, code, args);

  if (ctx->error)
    return;
  test_and_allocate_result (ctx, genkey);

  switch (code)
    {
    case STATUS_KEY_CREATED:
      if (args && *args)
	{
	  if (*args == 'B' || *args == 'P')
	    ctx->result.genkey->created_primary = 1;
	  if (*args == 'B' || *args == 'S')
	    ctx->result.genkey->created_sub = 1;
	}
      break;

    case STATUS_EOF:
      /* FIXME: Should return some more useful error value.  */
      if (!ctx->result.genkey->created_primary
	  && !ctx->result.genkey->created_sub)
	ctx->error = mk_error (General_Error);
      break;

    default:
      break;
    }
}


/**
 * gpgme_op_genkey:
 * @c: the context
 * @parms: XML string with the key parameters
 * @pubkey: Returns the public key
 * @seckey: Returns the secret key
 * 
 * Generate a new key and store the key in the default keyrings if
 * both @pubkey and @seckey are NULL.  If @pubkey and @seckey are
 * given, the newly created key will be returned in these data
 * objects.  This function just starts the gheneration and does not
 * wait for completion.
 *
 * Here is an example on how @parms should be formatted; for deatils
 * see the file doc/DETAILS from the GnuPG distribution.
 *
 * <literal>
 * <![CDATA[
 * <GnupgKeyParms format="internal">
 * Key-Type: DSA
 * Key-Length: 1024
 * Subkey-Type: ELG-E
 * Subkey-Length: 1024
 * Name-Real: Joe Tester
 * Name-Comment: with stupid passphrase
 * Name-Email: joe@foo.bar
 * Expire-Date: 0
 * Passphrase: abc
 * </GnupgKeyParms>
 * ]]>
 * </literal> 
 *
 * Strings should be given in UTF-8 encoding.  The format we support
 * for now is only "internal".  The content of the
 * &lt;GnupgKeyParms&gt; container is passed verbatim to GnuPG.
 * Control statements are not allowed.
 * 
 * Return value: 0 for success or an error code
 **/
GpgmeError
gpgme_op_genkey_start (GpgmeCtx ctx, const char *parms,
		       GpgmeData pubkey, GpgmeData seckey)
{
  int err = 0;
  const char *s, *s2, *sx;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  gpgme_data_release (ctx->help_data_1);
  ctx->help_data_1 = NULL;

  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    goto leave;

  if (!pubkey && !seckey)
    ; /* okay: Add key to the keyrings */
  else if (!pubkey || gpgme_data_get_type (pubkey) != GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
  else if (!seckey || gpgme_data_get_type (seckey) != GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
    
  if (pubkey)
    /* FIXME: Need some more things here.  */
    _gpgme_data_set_mode (pubkey, GPGME_DATA_MODE_IN);

  if (seckey)
    /* FIXME: Need some more things here.  */
    _gpgme_data_set_mode (seckey, GPGME_DATA_MODE_IN);

  if ((parms = strstr (parms, "<GnupgKeyParms ")) 
      && (s = strchr (parms, '>'))
      && (sx = strstr (parms, "format=\"internal\""))
      && sx < s
      && (s2 = strstr (s+1, "</GnupgKeyParms>")))
    {
      /* FIXME: Check that there are no control statements inside.  */
      err = gpgme_data_new_from_mem (&ctx->help_data_1, s+1, s2-s-1, 1);
    }
  else 
    err = mk_error (Invalid_Value);

  if (err)
    goto leave;
    
  _gpgme_data_set_mode (ctx->help_data_1, GPGME_DATA_MODE_OUT);

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_genkey (ctx->engine, ctx->help_data_1, ctx->use_armor,
				 pubkey, seckey);

  if (!err)
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


/**
 * gpgme_op_genkey:
 * @c: the context
 * @parms: XML string with the key parameters
 * @pubkey: Returns the public key
 * @seckey: Returns the secret key
 * 
 * Generate a new key and store the key in the default keyrings if both
 * @pubkey and @seckey are NULL.  If @pubkey and @seckey are given, the newly
 * created key will be returned in these data objects.
 * See gpgme_op_genkey_start() for a description of @parms.
 * 
 * Return value: 0 for success or an error code
 **/
GpgmeError
gpgme_op_genkey (GpgmeCtx ctx, const char *parms,
                 GpgmeData pubkey, GpgmeData seckey)
{
  GpgmeError err = gpgme_op_genkey_start (ctx, parms, pubkey, seckey);
  if (!err)
    gpgme_wait (ctx, &err, 1);
  return err;
}

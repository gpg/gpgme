/* genkey.c - Key generation.
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

#include "util.h"
#include "context.h"
#include "ops.h"


struct genkey_result
{
  int created_primary : 1;
  int created_sub : 1;
  char *fpr;
};
typedef struct genkey_result *GenKeyResult;

static void
release_genkey_result (void *hook)
{
  GenKeyResult result = (GenKeyResult) hook;
  
  if (result->fpr)
    free (result->fpr);
}


static GpgmeError
genkey_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GenKeyResult result;
  GpgmeError err = _gpgme_progress_status_handler (ctx, code, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, (void **) &result,
			       sizeof (*result), release_genkey_result);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_KEY_CREATED:
      if (args && *args)
	{
	  if (*args == 'B' || *args == 'P')
	    result->created_primary = 1;
	  if (*args == 'B' || *args == 'S')
	    result->created_sub = 1;
	  if (args[1] == ' ')
	    {
	      if (result->fpr)
		free (result->fpr);
	      result->fpr = strdup (&args[2]);
	      if (!result->fpr)
		return GPGME_Out_Of_Core;
	    }
	}
      break;

    case GPGME_STATUS_EOF:
      /* FIXME: Should return some more useful error value.  */
      if (!result->created_primary
	  && !result->created_sub)
	return GPGME_General_Error;
      break;

    default:
      break;
    }
  return 0;
}


static GpgmeError
_gpgme_op_genkey_start (GpgmeCtx ctx, int synchronous, const char *parms,
			GpgmeData pubkey, GpgmeData seckey)
{
  int err = 0;
  const char *s, *s2, *sx;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  gpgme_data_release (ctx->help_data_1);
  ctx->help_data_1 = NULL;

  if ((parms = strstr (parms, "<GnupgKeyParms ")) 
      && (s = strchr (parms, '>'))
      && (sx = strstr (parms, "format=\"internal\""))
      && sx < s
      && (s2 = strstr (s+1, "</GnupgKeyParms>")))
    {
      /* FIXME: Check that there are no control statements inside.  */
      s++;  /* Skip '>'.  */
      while (*s == '\n')
	s++;
      err = gpgme_data_new_from_mem (&ctx->help_data_1, s, s2-s, 1);
    }
  else 
    err = GPGME_Invalid_Value;

  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_genkey (ctx->engine, ctx->help_data_1, ctx->use_armor,
				 pubkey, seckey);

 leave:
  if (err)
    {
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
  return _gpgme_op_genkey_start (ctx, 0, parms, pubkey, seckey);
}


/**
 * gpgme_op_genkey:
 * @c: the context
 * @parms: XML string with the key parameters
 * @pubkey: Returns the public key
 * @seckey: Returns the secret key
 * @fpr: Returns the fingerprint of the key.
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
                 GpgmeData pubkey, GpgmeData seckey,
		 char **fpr)
{
  GpgmeError err = _gpgme_op_genkey_start (ctx, 1, parms, pubkey, seckey);
  if (!err)
    err = _gpgme_wait_one (ctx);
  if (!err && fpr)
    {
      GenKeyResult result;

      err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, (void **) &result,
				   -1, NULL);
      if (err)
	return err;

      if (result && result->fpr)
	{
	  *fpr = strdup (result->fpr);
	  if (!*fpr)
	    return GPGME_Out_Of_Core;
	}
      else
	*fpr = NULL;
    }
  return err;
}

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
#include <errno.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_genkey_result result;

  /* The key parameters passed to the crypto engine.  */
  gpgme_data_t key_parameter;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  
  if (opd->result.fpr)
    free (opd->result.fpr);
  if (opd->key_parameter)
    gpgme_data_release (opd->key_parameter);
}


gpgme_genkey_result_t
gpgme_op_genkey_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    return NULL;

  return &opd->result;
}


static gpgme_error_t
genkey_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  /* Pipe the status code through the progress status handler.  */
  err = _gpgme_progress_status_handler (ctx, code, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_KEY_CREATED:
      if (args && *args)
	{
	  if (*args == 'B' || *args == 'P')
	    opd->result.primary = 1;
	  if (*args == 'B' || *args == 'S')
	    opd->result.sub = 1;
	  if (args[1] == ' ')
	    {
	      if (opd->result.fpr)
		free (opd->result.fpr);
	      opd->result.fpr = strdup (&args[2]);
	      if (!opd->result.fpr)
		return gpg_error_from_errno (errno);
	    }
	}
      break;

    case GPGME_STATUS_EOF:
      /* FIXME: Should return some more useful error value.  */
      if (!opd->result.primary && !opd->result.sub)
	return gpg_error (GPG_ERR_GENERAL);
      break;

    default:
      break;
    }
  return 0;
}


static gpgme_error_t
get_key_parameter (const char *parms, gpgme_data_t *key_parameter)
{
  const char *content;
  const char *attrib;
  const char *endtag;

  /* Extract the key parameter from the XML structure.  */
  parms = strstr (parms, "<GnupgKeyParms ");
  if (!parms)
    return gpg_error (GPG_ERR_INV_VALUE);

  content = strchr (parms, '>');
  if (!content)
    return gpg_error (GPG_ERR_INV_VALUE);
  content++;

  attrib = strstr (parms, "format=\"internal\"");
  if (!attrib || attrib >= content)
    return gpg_error (GPG_ERR_INV_VALUE);

  endtag = strstr (content, "</GnupgKeyParms>");
  /* FIXME: Check that there are no control statements inside.  */
  while (*content == '\n')
    content++;

  return gpgme_data_new_from_mem (key_parameter, content,
				  endtag - content, 1);
}


static gpgme_error_t
genkey_start (gpgme_ctx_t ctx, int synchronous, const char *parms,
	      gpgme_data_t pubkey, gpgme_data_t seckey)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;
  
  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  err = get_key_parameter (parms, &opd->key_parameter);
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);

  return _gpgme_engine_op_genkey (ctx->engine, opd->key_parameter,
				  ctx->use_armor, pubkey, seckey);
}


/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
gpgme_error_t
gpgme_op_genkey_start (gpgme_ctx_t ctx, const char *parms,
		       gpgme_data_t pubkey, gpgme_data_t seckey)
{
  return genkey_start (ctx, 0, parms, pubkey, seckey);
}


/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
gpgme_error_t
gpgme_op_genkey (gpgme_ctx_t ctx, const char *parms, gpgme_data_t pubkey,
		 gpgme_data_t seckey)
{
  gpgme_error_t err;

  err = genkey_start (ctx, 1, parms, pubkey, seckey);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}

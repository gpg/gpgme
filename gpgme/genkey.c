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

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_genkey_result result;

  /* The key parameters passed to the crypto engine.  */
  GpgmeData key_parameter;
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


GpgmeGenKeyResult
gpgme_op_genkey_result (GpgmeCtx ctx)
{
  op_data_t opd;
  GpgmeError err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, (void **) &opd, -1, NULL);
  if (err || !opd)
    return NULL;

  return &opd->result;
}


static GpgmeError
genkey_status_handler (void *priv, GpgmeStatusCode code, char *args)
{
  GpgmeCtx ctx = (GpgmeCtx) priv;
  GpgmeError err;
  op_data_t opd;

  /* Pipe the status code through the progress status handler.  */
  err = _gpgme_progress_status_handler (ctx, code, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, (void **) &opd,
			       -1, NULL);
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
		return GPGME_Out_Of_Core;
	    }
	}
      break;

    case GPGME_STATUS_EOF:
      /* FIXME: Should return some more useful error value.  */
      if (!opd->result.primary && !opd->result.sub)
	return GPGME_General_Error;
      break;

    default:
      break;
    }
  return 0;
}


static GpgmeError
get_key_parameter (const char *parms, GpgmeData *key_parameter)
{
  const char *content;
  const char *attrib;
  const char *endtag;

  /* Extract the key parameter from the XML structure.  */
  parms = strstr (parms, "<GnupgKeyParms ");
  if (!parms)
    return GPGME_Invalid_Value;

  content = strchr (parms, '>');
  if (!content)
    return GPGME_Invalid_Value;
  content++;

  attrib = strstr (parms, "format=\"internal\"");
  if (!attrib || attrib >= content)
    return GPGME_Invalid_Value;

  endtag = strstr (content, "</GnupgKeyParms>");
  /* FIXME: Check that there are no control statements inside.  */
  while (*content == '\n')
    content++;

  return gpgme_data_new_from_mem (key_parameter, content,
				  endtag - content, 0);
}


static GpgmeError
genkey_start (GpgmeCtx ctx, int synchronous, const char *parms,
	      GpgmeData pubkey, GpgmeData seckey)
{
  GpgmeError err;
  op_data_t opd;
  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;
  
  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, (void **) &opd,
			       sizeof (*opd), release_op_data);
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
GpgmeError
gpgme_op_genkey_start (GpgmeCtx ctx, const char *parms,
		       GpgmeData pubkey, GpgmeData seckey)
{
  return genkey_start (ctx, 0, parms, pubkey, seckey);
}


/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
GpgmeError
gpgme_op_genkey (GpgmeCtx ctx, const char *parms, GpgmeData pubkey,
		 GpgmeData seckey)
{
  GpgmeError err;

  err = genkey_start (ctx, 1, parms, pubkey, seckey);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}

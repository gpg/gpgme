/* genkey.c - Key generation.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2016 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"
#include "util.h"


typedef struct
{
  struct _gpgme_op_genkey_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  /* The error code from certain ERROR status lines or 0.  */
  gpg_error_t error_code;

  /* Flag to indicate that a UID is to be added.  */
  gpg_error_t uidmode;

  /* The key parameters passed to the crypto engine.  */
  gpgme_data_t key_parameter;

  /* Flag to indicate that an ADSK is to be added.  */
  unsigned int adskmode : 1;
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

  TRACE_BEG (DEBUG_CTX, "gpgme_op_genkey_result", ctx, "");

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  TRACE_LOG  ("fpr = %s, %s, %s", opd->result.fpr,
	      opd->result.primary ? "primary" : "no primary",
	      opd->result.sub ? "sub" : "no sub");

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}



/* Parse an error status line.  Return the error location and the
   error code.  The function may modify ARGS. */
static char *
parse_error (char *args, gpg_error_t *r_err)
{
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
    {
      *r_err = trace_gpg_error (GPG_ERR_INV_ENGINE);
      return NULL;
    }

  *r_err = atoi (which);

  return where;
}


static gpgme_error_t
genkey_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  char *loc;

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
            {
              opd->result.primary = 1;
              opd->result.uid = 1;
            }
	  if (*args == 'B' || *args == 'S')
	    opd->result.sub = 1;
	  if (args[1] == ' ')
	    {
	      if (opd->result.fpr)
		free (opd->result.fpr);
	      opd->result.fpr = strdup (&args[2]);
	      if (!opd->result.fpr)
		return gpg_error_from_syserror ();
	    }
	}
      break;

    case GPGME_STATUS_ERROR:
      loc = parse_error (args, &err);
      if (!loc)
        return err;
      if (!opd->error_code)
        opd->error_code = err;
      break;

    case GPGME_STATUS_FAILURE:
      if (!opd->failure_code
          || gpg_err_code (opd->failure_code) == GPG_ERR_GENERAL)
        opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      if (opd->error_code)
        return opd->error_code;
      else if (!opd->uidmode && !opd->adskmode && !opd->result.primary && !opd->result.sub)
	return gpg_error (GPG_ERR_GENERAL);
      else if (opd->failure_code)
        return opd->failure_code;
      else if (opd->uidmode == 1)
        opd->result.uid = 1;  /* We have no status line, thus this hack.  */
      break;

    case GPGME_STATUS_INQUIRE_MAXLEN:
      if (ctx->status_cb && !ctx->full_status)
        {
          err = ctx->status_cb (ctx->status_cb_value, "INQUIRE_MAXLEN", args);
          if (err)
            return err;
        }
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
  if (!endtag)
    endtag = content + strlen (content);

  /* FIXME: Check that there are no control statements inside.  */
  while (content < endtag
         && (content[0] == '\n'
             || (content[0] == '\r' && content[1] == '\n')))
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

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
        (ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
        return err;
    }

  return _gpgme_engine_op_genkey (ctx->engine,
                                  NULL, NULL, 0, 0, NULL, 0,
                                  opd->key_parameter,
				  ctx->use_armor? GENKEY_EXTRAFLAG_ARMOR:0,
                                  pubkey, seckey);
}


/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
gpgme_error_t
gpgme_op_genkey_start (gpgme_ctx_t ctx, const char *parms,
		       gpgme_data_t pubkey, gpgme_data_t seckey)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_genkey_start", ctx,
	      "pubkey=%p, seckey=%p", pubkey, seckey);
  TRACE_LOGBUF (parms, parms? strlen (parms):0);

  if (!ctx || !parms)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = genkey_start (ctx, 0, parms, pubkey, seckey);
  return TRACE_ERR (err);
}


/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
gpgme_error_t
gpgme_op_genkey (gpgme_ctx_t ctx, const char *parms, gpgme_data_t pubkey,
		 gpgme_data_t seckey)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_genkey", ctx,
	      "pubkey=%p, seckey=%p", pubkey, seckey);
  TRACE_LOGBUF (parms, parms? strlen (parms):0);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = genkey_start (ctx, 1, parms, pubkey, seckey);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}



static gpgme_error_t
createkey_start (gpgme_ctx_t ctx, int synchronous,
                 const char *userid, const char *algo,
                 unsigned long reserved, unsigned long expires,
                 gpgme_key_t anchorkey, unsigned int flags)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (reserved || anchorkey || !userid)
    return gpg_error (GPG_ERR_INV_ARG);

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
        (ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
        return err;
    }

  return _gpgme_engine_op_genkey (ctx->engine,
                                  userid, algo, reserved, expires,
                                  anchorkey, flags,
                                  NULL,
				  ctx->use_armor? GENKEY_EXTRAFLAG_ARMOR:0,
                                  NULL, NULL);

}


gpgme_error_t
gpgme_op_createkey_start (gpgme_ctx_t ctx, const char *userid, const char *algo,
                          unsigned long reserved, unsigned long expires,
                          gpgme_key_t anchorkey, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_createkey_start", ctx,
	      "userid='%s', algo='%s' flags=0x%x", userid, algo, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = createkey_start (ctx, 0,
                         userid, algo, reserved, expires, anchorkey, flags);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_createkey (gpgme_ctx_t ctx, const char *userid, const char *algo,
                    unsigned long reserved, unsigned long expires,
                    gpgme_key_t anchorkey, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_createkey", ctx,
	      "userid='%s', algo='%s' flags=0x%x", userid, algo, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = createkey_start (ctx, 1,
                         userid, algo, reserved, expires, anchorkey, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}



static gpgme_error_t
createsubkey_start (gpgme_ctx_t ctx, int synchronous,
                    gpgme_key_t key,
                    const char *algo,
                    unsigned long reserved, unsigned long expires,
                    unsigned int flags)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  if (ctx->protocol != GPGME_PROTOCOL_OPENPGP)
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  if (reserved || !key)
    return gpg_error (GPG_ERR_INV_ARG);

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
        (ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
        return err;
    }

  if (flags & GPGME_CREATE_ADSK)
    opd->adskmode = 1;

  return _gpgme_engine_op_genkey (ctx->engine,
                                  NULL, algo, reserved, expires,
                                  key, flags,
                                  NULL,
				  ctx->use_armor? GENKEY_EXTRAFLAG_ARMOR:0,
                                  NULL, NULL);

}


/* Add a subkey to an existing KEY.  */
gpgme_error_t
gpgme_op_createsubkey_start (gpgme_ctx_t ctx, gpgme_key_t key, const char *algo,
                             unsigned long reserved, unsigned long expires,
                             unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_createsubkey_start", ctx,
	      "key=%p, algo='%s' flags=0x%x", key, algo, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = createsubkey_start (ctx, 0, key, algo, reserved, expires, flags);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_createsubkey (gpgme_ctx_t ctx, gpgme_key_t key, const char *algo,
                       unsigned long reserved, unsigned long expires,
                       unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_createsubkey", ctx,
	      "key=%p, algo='%s' flags=0x%x", key, algo, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = createsubkey_start (ctx, 1, key, algo, reserved, expires, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}



static gpgme_error_t
addrevuid_start (gpgme_ctx_t ctx, int synchronous, int extraflags,
                 gpgme_key_t key, const char *userid, unsigned int flags)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  if (ctx->protocol != GPGME_PROTOCOL_OPENPGP)
    return gpgme_error (GPG_ERR_UNSUPPORTED_PROTOCOL);

  if (!key || !userid)
    return gpg_error (GPG_ERR_INV_ARG);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_GENKEY, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  opd->uidmode = extraflags? 2 : 1;

  _gpgme_engine_set_status_handler (ctx->engine, genkey_status_handler, ctx);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
        (ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
        return err;
    }

  return _gpgme_engine_op_genkey (ctx->engine,
                                  userid, NULL, 0, 0,
                                  key, flags,
                                  NULL,
				  extraflags,
                                  NULL, NULL);

}


/* Add USERID to an existing KEY.  */
gpgme_error_t
gpgme_op_adduid_start (gpgme_ctx_t ctx,
                       gpgme_key_t key, const char *userid, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_adduid_start", ctx,
	      "uid='%s' flags=0x%x", userid, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = addrevuid_start (ctx, 0, 0, key, userid, flags);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_adduid (gpgme_ctx_t ctx,
                 gpgme_key_t key, const char *userid, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_adduid", ctx,
	      "uid='%s' flags=0x%x", userid, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = addrevuid_start (ctx, 1, 0, key, userid, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* Revoke USERID from KEY.  */
gpgme_error_t
gpgme_op_revuid_start (gpgme_ctx_t ctx,
                       gpgme_key_t key, const char *userid, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_revuid_start", ctx,
	      "uid='%s' flags=0x%x", userid, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = addrevuid_start (ctx, 0, GENKEY_EXTRAFLAG_REVOKE, key, userid, flags);
  return TRACE_ERR (err);
}


gpgme_error_t
gpgme_op_revuid (gpgme_ctx_t ctx,
                 gpgme_key_t key, const char *userid, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_revuid", ctx,
	      "uid='%s' flags=0x%x", userid, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  err = addrevuid_start (ctx, 1, GENKEY_EXTRAFLAG_REVOKE, key, userid, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* Set a flag on the USERID of KEY.  The only supported flag right now
 * is "primary" to mark the primary key.  */
static gpg_error_t
set_uid_flag (gpgme_ctx_t ctx, int synchronous,
              gpgme_key_t key, const char *userid,
              const char *name, const char *value)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_set_uid_flag", ctx,
	      "%d uid='%s' '%s'='%s'", synchronous, userid, name, value);

  if (!ctx || !name || !key || !userid)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_ARG));

  if (!strcmp (name, "primary"))
    {
      if (value)
        err = gpg_error (GPG_ERR_INV_ARG);
      else
        err = addrevuid_start (ctx, synchronous,
                               GENKEY_EXTRAFLAG_SETPRIMARY, key, userid, 0);
    }
  else
    return err = gpg_error (GPG_ERR_UNKNOWN_NAME);

  if (synchronous && !err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* See set_uid_flag. */
gpgme_error_t
gpgme_op_set_uid_flag_start (gpgme_ctx_t ctx,
                             gpgme_key_t key, const char *userid,
                             const char *name, const char *value)
{
  return set_uid_flag (ctx, 0, key, userid, name, value);
}


/* See set_uid_flag.  This is the synchronous variant.  */
gpgme_error_t
gpgme_op_set_uid_flag (gpgme_ctx_t ctx,
                       gpgme_key_t key, const char *userid,
                       const char *name, const char *value)
{
  return set_uid_flag (ctx, 1, key, userid, name, value);
}

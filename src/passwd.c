/* passwd.c - Passphrase changing function
 * Copyright (C) 2010 g10 Code GmbH
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

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  int success_seen;
  int error_seen;
} *op_data_t;



/* Parse an error status line and return the error code.  */
static gpgme_error_t
parse_error (char *args)
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
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  err = atoi (which);

  if (!strcmp (where, "keyedit.passwd"))
    return err;

  return 0;
}


static gpgme_error_t
passwd_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSWD, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_ERROR:
      err = parse_error (args);
      if (err)
        opd->error_seen = 1;
      break;

    case GPGME_STATUS_SUCCESS:
      opd->success_seen = 1;
      break;

    case GPGME_STATUS_FAILURE:
      if (!opd->failure_code
          || gpg_err_code (opd->failure_code) == GPG_ERR_GENERAL)
        opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      /* In case the OpenPGP engine does not properly implement the
         passwd command we won't get a success status back and thus we
         conclude that this operation is not supported.  This is for
         example the case for GnuPG < 2.0.16.  Note that this test is
         obsolete for assuan based engines because they will properly
         return an error for an unknown command.  */
      if (ctx->protocol == GPGME_PROTOCOL_OpenPGP
          && !opd->error_seen && !opd->success_seen)
        err = gpg_error (GPG_ERR_NOT_SUPPORTED);
      else if (opd->failure_code)
        err = opd->failure_code;
      break;

    default:
      break;
    }

  return err;
}


static gpgme_error_t
passwd_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t key,
              unsigned int flags)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  if (!key)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (flags)
    return gpg_error (GPG_ERR_INV_FLAG);

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSWD, &hook, sizeof (*opd), NULL);
  opd = hook;
  if (err)
    return err;

  opd->success_seen = 0;
  opd->error_seen = 0;

  _gpgme_engine_set_status_handler (ctx->engine, passwd_status_handler, ctx);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
        (ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
        return err;
    }

  return _gpgme_engine_op_passwd (ctx->engine, key, flags);
}



/* Change the passphrase for KEY.  FLAGS is reserved for future use
   and must be passed as 0.  The engine is expected to present a user
   interface to enter the old and the new passphrase.  This is the
   asynchronous variant.

   Note that if ever the need arises to supply a passphrase we can do
   this with a flag value and the passphrase callback feature.  */
gpgme_error_t
gpgme_op_passwd_start (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags)
{
  gpg_error_t err;
  TRACE_BEG  (DEBUG_CTX, "gpgme_op_passwd_start", ctx,
	      "key=%p, flags=0x%x", key, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = passwd_start (ctx, 0, key, flags);
  return TRACE_ERR (err);
}


/* Change the passphrase for KEY.  FLAGS is reserved for future use
   and must be passed as 0.  This is the synchronous variant.  */
gpgme_error_t
gpgme_op_passwd (gpgme_ctx_t ctx, gpgme_key_t key, unsigned int flags)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_passwd", ctx,
	      "key=%p, flags=0x%x", key, flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = passwd_start (ctx, 1, key, flags);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


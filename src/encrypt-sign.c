/* encrypt-sign.c -  encrypt and verify functions
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH
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


static gpgme_error_t
encrypt_sign_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_encrypt_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_sign_status_handler (priv, code, args);
  return err;
}


static gpgme_error_t
encrypt_sym_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_sign_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_passphrase_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_encrypt_status_handler (priv, code, args);
  return err;
}


static gpgme_error_t
encrypt_sign_start (gpgme_ctx_t ctx, int synchronous, gpgme_key_t recp[],
                    const char *recpstring,
		    gpgme_encrypt_flags_t flags,
		    gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;
  int symmetric;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  symmetric = (!recp && !recpstring) || (flags & GPGME_ENCRYPT_SYMMETRIC);

  if (!plain)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!cipher)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (recp && !*recp)
    return gpg_error (GPG_ERR_INV_VALUE);

  err = _gpgme_op_encrypt_init_result (ctx, flags & GPGME_ENCRYPT_ARCHIVE);
  if (err)
    return err;

  err = _gpgme_op_sign_init_result (ctx, 0);
  if (err)
    return err;

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
	(ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine,
                                    symmetric
                                    ? encrypt_sym_status_handler
                                    : encrypt_sign_status_handler,
				    ctx);

  return _gpgme_engine_op_encrypt_sign (ctx->engine, recp, recpstring,
                                        flags, plain,
					cipher, ctx->use_armor,
					ctx /* FIXME */);
}


/* Old version of gpgme_op_encrypt_sign_ext_start w/o RECPSTRING.  */
gpgme_error_t
gpgme_op_encrypt_sign_start (gpgme_ctx_t ctx, gpgme_key_t recp[],
			     gpgme_encrypt_flags_t flags,
			     gpgme_data_t plain, gpgme_data_t cipher)
{
  return gpgme_op_encrypt_sign_ext_start (ctx, recp, NULL,
                                          flags, plain, cipher);
}


/* Old version of gpgme_op_encrypt_sign_ext w/o RECPSTRING.  */
gpgme_error_t
gpgme_op_encrypt_sign (gpgme_ctx_t ctx, gpgme_key_t recp[],
		       gpgme_encrypt_flags_t flags,
		       gpgme_data_t plain, gpgme_data_t cipher)
{
  return gpgme_op_encrypt_sign_ext (ctx, recp, NULL, flags, plain, cipher);
}


/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
 * store the resulting ciphertext in CIPHER.  Also sign the ciphertext
 * with the signers in CTX.  */
gpgme_error_t
gpgme_op_encrypt_sign_ext (gpgme_ctx_t ctx, gpgme_key_t recp[],
                           const char *recpstring,
                           gpgme_encrypt_flags_t flags,
                           gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_encrypt_sign", ctx,
	      "flags=0x%x, plain=%p, cipher=%p", flags, plain, cipher);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && (recp || recpstring))
    {
      if (recp)
        {
          int i = 0;

          while (recp[i])
            {
              TRACE_LOG  ("recipient[%i] = %p (%s)", i, recp[i],
                          (recp[i]->subkeys && recp[i]->subkeys->fpr) ?
                          recp[i]->subkeys->fpr : "invalid");
              i++;
            }
        }
      else
        {
          TRACE_LOG  ("recipients = '%s'", recpstring);
        }
    }

  err = encrypt_sign_start (ctx, 1, recp, recpstring, flags, plain, cipher);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
   store the resulting ciphertext in CIPHER.  Also sign the ciphertext
   with the signers in CTX.  */
gpgme_error_t
gpgme_op_encrypt_sign_ext_start (gpgme_ctx_t ctx, gpgme_key_t recp[],
                                 const char *recpstring,
                                 gpgme_encrypt_flags_t flags,
                                 gpgme_data_t plain, gpgme_data_t cipher)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_encrypt_sign_start", ctx,
	      "flags=0x%x, plain=%p, cipher=%p", flags, plain, cipher);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && (recp || recpstring))
    {
      if (recp)
        {
          int i = 0;

          while (recp[i])
            {
              TRACE_LOG  ("recipient[%i] = %p (%s)", i, recp[i],
                          (recp[i]->subkeys && recp[i]->subkeys->fpr) ?
                          recp[i]->subkeys->fpr : "invalid");
              i++;
            }
        }
      else
        {
          TRACE_LOG  ("recipients = '%s'", recpstring);
        }
    }

  err = encrypt_sign_start (ctx, 0, recp, recpstring, flags, plain, cipher);
  return err;
}

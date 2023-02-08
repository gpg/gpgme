/* decrypt-verify.c - Decrypt and verify function.
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

#include <assert.h>

#include "debug.h"
#include "gpgme.h"
#include "ops.h"


static gpgme_error_t
decrypt_verify_status_handler (void *priv, gpgme_status_code_t code,
			       char *args)
{
  gpgme_error_t err;
  gpgme_error_t err2;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_decrypt_status_handler (priv, code, args);
  /* Allow finalization of signature verification even if previous handler
   * returned NO DATA error which just means that the data wasn't encrypted. */
  if (!err
      || (code == GPGME_STATUS_EOF && gpg_err_code (err) == GPG_ERR_NO_DATA))
    err2 = _gpgme_verify_status_handler (priv, code, args);
  return err ? err : err2;
}


static gpgme_error_t
decrypt_verify_start (gpgme_ctx_t ctx, int synchronous,
                      gpgme_decrypt_flags_t flags,
		      gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err;

  assert ((flags & GPGME_DECRYPT_VERIFY));

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_decrypt_init_result (ctx, plain);
  if (err)
    return err;

  err = _gpgme_op_verify_init_result (ctx);
  if (err)
    return err;

  if (!cipher)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!plain)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
	(ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine,
				    decrypt_verify_status_handler, ctx);

  return _gpgme_engine_op_decrypt (ctx->engine,
                                   flags,
                                   cipher, plain,
                                   ctx->export_session_keys,
                                   ctx->override_session_key,
                                   ctx->auto_key_retrieve);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt_verify_start (gpgme_ctx_t ctx, gpgme_data_t cipher,
			       gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt_verify_start", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = decrypt_verify_start (ctx, 0, GPGME_DECRYPT_VERIFY, cipher, plain);
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt_verify (gpgme_ctx_t ctx, gpgme_data_t cipher,
			 gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt_verify", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = decrypt_verify_start (ctx, 1, GPGME_DECRYPT_VERIFY, cipher, plain);
  if (!err)
    err = _gpgme_wait_one (ctx);
  ctx->ignore_mdc_error = 0;  /* Always reset.  */
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt_ext_start (gpgme_ctx_t ctx,
                            gpgme_decrypt_flags_t flags,
                            gpgme_data_t cipher,
                            gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt_ext_start", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if ((flags & GPGME_DECRYPT_VERIFY))
    err = decrypt_verify_start (ctx, 0, flags, cipher, plain);
  else
    err = _gpgme_decrypt_start (ctx, 0, flags, cipher, plain);
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt_ext (gpgme_ctx_t ctx,
                      gpgme_decrypt_flags_t flags,
                      gpgme_data_t cipher,
                      gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt_ext", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if ((flags & GPGME_DECRYPT_VERIFY))
    err = decrypt_verify_start (ctx, 1, flags, cipher, plain);
  else
    err = _gpgme_decrypt_start (ctx, 1, flags, cipher, plain);
  if (!err)
    err = _gpgme_wait_one (ctx);
  ctx->ignore_mdc_error = 0;  /* Always reset.  */
  return TRACE_ERR (err);
}

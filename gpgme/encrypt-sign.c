/* encrypt-sign.c -  encrypt and verify functions
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"
#include "context.h"
#include "ops.h"


static GpgmeError
encrypt_sign_status_handler (void *priv, GpgmeStatusCode code, char *args)
{
  return _gpgme_encrypt_status_handler (priv, code, args)
    || _gpgme_sign_status_handler (priv, code, args);
}


static GpgmeError
_gpgme_op_encrypt_sign_start (GpgmeCtx ctx, int synchronous,
			      GpgmeRecipients recp,
			      GpgmeData plain, GpgmeData cipher)
{
  GpgmeError err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_encrypt_init_result (ctx);
  if (err)
    return err;

  err = _gpgme_op_sign_init_result (ctx);
  if (err)
    return err;

  if (!plain)
    return GPGME_No_Data;
  if (!cipher)
    return GPGME_Invalid_Value;

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler (ctx->engine,
					       _gpgme_passphrase_command_handler,
					       ctx, NULL);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine,
				    encrypt_sign_status_handler, ctx);

  return _gpgme_engine_op_encrypt_sign (ctx->engine, recp, plain, cipher,
					ctx->use_armor, ctx /* FIXME */);
}

GpgmeError
gpgme_op_encrypt_sign_start (GpgmeCtx ctx, GpgmeRecipients recp,
			      GpgmeData plain, GpgmeData cipher)
{
  return _gpgme_op_encrypt_sign_start (ctx, 0, recp, plain, cipher);
}


/**
 * gpgme_op_encrypt_sign:
 * @ctx: The context
 * @recp: The set of recipients
 * @plain: plaintext input
 * @cipher: signed ciphertext
 * 
 * This function encrypts @plain for all recipients in recp, signs it,
 * and returns the ciphertext in @out.  The function does wait for the
 * result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_encrypt_sign (GpgmeCtx ctx, GpgmeRecipients recp,
		       GpgmeData plain, GpgmeData cipher)
{
  GpgmeError err = _gpgme_op_encrypt_sign_start (ctx, 1, recp, plain, cipher);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}

/* decrypt.c -  decrypt functions
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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


struct decrypt_result_s
{
  int okay;
  int failed;
};


void
_gpgme_release_decrypt_result (DecryptResult result)
{
  if (!result)
    return;
  xfree (result);
}


void
_gpgme_decrypt_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  _gpgme_passphrase_status_handler (ctx, code, args);

  if (ctx->error)
    return;
  test_and_allocate_result (ctx, decrypt);

  switch (code)
    {
    case STATUS_EOF:
      if (ctx->result.decrypt->failed)
	ctx->error = mk_error (Decryption_Failed);
      else if (!ctx->result.decrypt->okay)
	ctx->error = mk_error (No_Data);
      break;

    case STATUS_DECRYPTION_OKAY:
      ctx->result.decrypt->okay = 1;
      break;

    case STATUS_DECRYPTION_FAILED:
      ctx->result.decrypt->failed = 1;
      break;
        
    default:
      /* Ignore all other codes.  */
      break;
    }
}


GpgmeError
_gpgme_decrypt_start (GpgmeCtx ctx, GpgmeData ciph, GpgmeData plain,
		      void *status_handler)
{
  GpgmeError err = 0;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_release_result (ctx);

  /* Create a process object.  */
  _gpgme_engine_release (ctx->engine);
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    goto leave;

  /* Check the supplied data.  */
  if (!ciph || gpgme_data_get_type (ciph) == GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (No_Data);
      goto leave;
    }
  _gpgme_data_set_mode (ciph, GPGME_DATA_MODE_OUT);

  if (gpgme_data_get_type (plain) != GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
  _gpgme_data_set_mode (plain, GPGME_DATA_MODE_IN);

  err = _gpgme_passphrase_start (ctx);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_decrypt (ctx->engine, ciph, plain);

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


GpgmeError
gpgme_op_decrypt_start (GpgmeCtx ctx, GpgmeData ciph, GpgmeData plain)
{
  return _gpgme_decrypt_start (ctx, ciph, plain,
			       _gpgme_decrypt_status_handler);
}


/**
 * gpgme_op_decrypt:
 * @ctx: The context
 * @in: ciphertext input
 * @out: plaintext output
 * 
 * This function decrypts @in to @out.
 * Other parameters are take from the context @ctx.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_decrypt (GpgmeCtx ctx, GpgmeData in, GpgmeData out)
{
  GpgmeError err = gpgme_op_decrypt_start (ctx, in, out);
  if (!err)
    {
      gpgme_wait (ctx, 1);
      err = ctx->error;
    }
  return err;
}

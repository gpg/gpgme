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

static GpgmeError
create_result_struct (GpgmeCtx ctx)
{
  assert (!ctx->result.decrypt);
  ctx->result.decrypt = xtrycalloc (1, sizeof *ctx->result.decrypt);
  if (!ctx->result.decrypt)
    return mk_error (Out_Of_Core);
  return 0;    
}

void
_gpgme_decrypt_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  _gpgme_passphrase_status_handler (ctx, code, args);

  if (ctx->out_of_core)
    return;

  if (! ctx->result.decrypt)
    {
      if (create_result_struct (ctx))
	{
	  ctx->out_of_core = 1;
	  return;
	}
    }

  switch (code)
    {
    case STATUS_EOF:
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
  int i;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_release_result (ctx);
  ctx->out_of_core = 0;

  /* Do some checks.  */
 
  /* Create a process object.  */
  _gpgme_gpg_release (ctx->gpg);
  err = _gpgme_gpg_new (&ctx->gpg);
  if (err)
    goto leave;

  _gpgme_gpg_set_status_handler (ctx->gpg, status_handler, ctx);

  err = _gpgme_passphrase_start (ctx);
  if (err)
    goto leave;

  /* Build the commandline.  */
  _gpgme_gpg_add_arg (ctx->gpg, "--decrypt");
  for (i = 0; i < ctx->verbosity; i++)
    _gpgme_gpg_add_arg (ctx->gpg, "--verbose");

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

  /* Tell the gpg object about the data.  */
  _gpgme_gpg_add_arg (ctx->gpg, "--output");
  _gpgme_gpg_add_arg (ctx->gpg, "-");
  _gpgme_gpg_add_data (ctx->gpg, plain, 1);
  _gpgme_gpg_add_data (ctx->gpg, ciph, 0);

  /* And kick off the process.  */
  err = _gpgme_gpg_spawn (ctx->gpg, ctx);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_gpg_release (ctx->gpg);
      ctx->gpg = NULL;
    }
  return err;
}

GpgmeError
gpgme_op_decrypt_start (GpgmeCtx ctx, GpgmeData ciph, GpgmeData plain)
{
  return _gpgme_decrypt_start (ctx, ciph, plain,
			       _gpgme_decrypt_status_handler);
}

GpgmeError
_gpgme_decrypt_result (GpgmeCtx ctx)
{
  GpgmeError err = 0;

  if (!ctx->result.decrypt)
    err = mk_error (General_Error);
  else if (ctx->out_of_core)
    err = mk_error (Out_Of_Core);
  else
    {
      err = _gpgme_passphrase_result (ctx);
      if (! err)
	{
	  if (ctx->result.decrypt->failed)
	    err = mk_error (Decryption_Failed);
	  else if (!ctx->result.decrypt->okay)
	    err = mk_error (No_Data);
	}
    }
  return err;
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
      err = _gpgme_decrypt_result (ctx);
      ctx->pending = 0;
    }
  return err;
}

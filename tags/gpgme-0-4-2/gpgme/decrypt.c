/* decrypt.c - Decrypt function.
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
#include "util.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_decrypt_result result;

  int okay;
  int failed;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;

  if (opd->result.unsupported_algorithm)
    free (opd->result.unsupported_algorithm);
}


gpgme_decrypt_result_t
gpgme_op_decrypt_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    return NULL;

  return &opd->result;
}


gpgme_error_t
_gpgme_decrypt_status_handler (void *priv, gpgme_status_code_t code,
			       char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_passphrase_status_handler (priv, code, args);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_EOF:
      /* FIXME: These error values should probably be attributed to
	 the underlying crypto engine (as error source).  */
      if (opd->failed)
	return gpg_error (GPG_ERR_DECRYPT_FAILED);
      else if (!opd->okay)
	return gpg_error (GPG_ERR_NO_DATA);
      break;

    case GPGME_STATUS_DECRYPTION_OKAY:
      opd->okay = 1;
      break;

    case GPGME_STATUS_DECRYPTION_FAILED:
      opd->failed = 1;
      break;

    case GPGME_STATUS_ERROR:
      {
	const char d_alg[] = "decrypt.algorithm";
	const char u_alg[] = "Unsupported_Algorithm";
	if (!strncmp (args, d_alg, sizeof (d_alg) - 1))
	  {
	    args += sizeof (d_alg);
	    while (*args == ' ')
	      args++;

	    if (!strncmp (args, u_alg, sizeof (u_alg) - 1))
	      {
		char *end;

		args += sizeof (u_alg);
		while (*args == ' ')
		  args++;

		end = strchr (args, ' ');
		if (end)
		  *end = '\0';

		if (!(*args == '?' && *(args + 1) == '\0'))
		  {
		    opd->result.unsupported_algorithm = strdup (args);
		    if (!opd->result.unsupported_algorithm)
		      return gpg_error_from_errno (errno);
		  }
	      }
	  }
      }
      break;
        
    default:
      break;
    }

  return 0;
}


static gpgme_error_t
decrypt_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_error_t err;

  err = _gpgme_progress_status_handler (priv, code, args);
  if (!err)
    err = _gpgme_decrypt_status_handler (priv, code, args);
  return err;
}


gpgme_error_t
_gpgme_op_decrypt_init_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;

  return _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook,
				sizeof (*opd), release_op_data);
}


static gpgme_error_t
decrypt_start (gpgme_ctx_t ctx, int synchronous,
		      gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_decrypt_init_result (ctx);
  if (err)
    return err;

  if (!cipher)
    return gpg_error (GPG_ERR_NO_DATA);
  if (!plain)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (err)
    return err;

  if (ctx->passphrase_cb)
    {
      err = _gpgme_engine_set_command_handler
	(ctx->engine, _gpgme_passphrase_command_handler, ctx, NULL);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine, decrypt_status_handler, ctx);

  return _gpgme_engine_op_decrypt (ctx->engine, cipher, plain);
}


gpgme_error_t
gpgme_op_decrypt_start (gpgme_ctx_t ctx, gpgme_data_t cipher,
			gpgme_data_t plain)
{
  return decrypt_start (ctx, 0, cipher, plain);
}


/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt (gpgme_ctx_t ctx, gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err = decrypt_start (ctx, 1, cipher, plain);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}

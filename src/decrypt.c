/* decrypt.c - Decrypt function.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004 g10 Code GmbH

   This file is part of GPGME.

   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.

   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "debug.h"
#include "gpgme.h"
#include "util.h"
#include "context.h"
#include "ops.h"



typedef struct
{
  struct _gpgme_op_decrypt_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  int okay;
  int failed;

  /* A pointer to the next pointer of the last recipient in the list.
     This makes appending new invalid signers painless while
     preserving the order.  */
  gpgme_recipient_t *last_recipient_p;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_recipient_t recipient = opd->result.recipients;

  if (opd->result.unsupported_algorithm)
    free (opd->result.unsupported_algorithm);

  if (opd->result.file_name)
    free (opd->result.file_name);

  while (recipient)
    {
      gpgme_recipient_t next = recipient->next;
      free (recipient);
      recipient = next;
    }
}


gpgme_decrypt_result_t
gpgme_op_decrypt_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_decrypt_result", ctx);

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC0 ("result=(null)");
      return NULL;
    }

  if (_gpgme_debug_trace ())
    {
      gpgme_recipient_t rcp;

      if (opd->result.unsupported_algorithm)
	{
	  TRACE_LOG1 ("result: unsupported_algorithm: %s",
		      opd->result.unsupported_algorithm);
	}
      if (opd->result.wrong_key_usage)
	{
	  TRACE_LOG ("result: wrong key usage");
	}
      rcp = opd->result.recipients;
      while (rcp)
	{
	  TRACE_LOG3 ("result: recipient: keyid=%s, pubkey_algo=%i, "
		      "status=%s", rcp->keyid, rcp->pubkey_algo,
		      gpg_strerror (rcp->status));
	  rcp = rcp->next;
	}
      if (opd->result.file_name)
	{
	  TRACE_LOG1 ("result: original file name: %s", opd->result.file_name);
	}
    }

  TRACE_SUC1 ("result=%p", &opd->result);
  return &opd->result;
}


static gpgme_error_t
parse_enc_to (char *args, gpgme_recipient_t *recp, gpgme_protocol_t protocol)
{
  gpgme_recipient_t rec;
  char *tail;
  int i;

  rec = malloc (sizeof (*rec));
  if (!rec)
    return gpg_error_from_syserror ();

  rec->next = NULL;
  rec->keyid = rec->_keyid;
  rec->status = 0;

  for (i = 0; i < sizeof (rec->_keyid) - 1; i++)
    {
      if (args[i] == '\0' || args[i] == ' ')
	break;

      rec->_keyid[i] = args[i];
    }
  rec->_keyid[i] = '\0';

  args = &args[i];
  if (*args != '\0' && *args != ' ')
    {
      free (rec);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }

  while (*args == ' ')
    args++;

  if (*args)
    {
      gpg_err_set_errno (0);
      rec->pubkey_algo = _gpgme_map_pk_algo (strtol (args, &tail, 0), protocol);
      if (errno || args == tail || *tail != ' ')
	{
	  /* The crypto backend does not behave.  */
	  free (rec);
	  return trace_gpg_error (GPG_ERR_INV_ENGINE);
	}
    }

  /* FIXME: The key length is always 0 right now, so no need to parse
     it.  */

  *recp = rec;
  return 0;
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
    case GPGME_STATUS_FAILURE:
      opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      /* FIXME: These error values should probably be attributed to
	 the underlying crypto engine (as error source).  */
      if (opd->failed)
	return gpg_error (GPG_ERR_DECRYPT_FAILED);
      else if (!opd->okay)
	return gpg_error (GPG_ERR_NO_DATA);
      else if (opd->failure_code)
        return opd->failure_code;
      break;

    case GPGME_STATUS_DECRYPTION_INFO:
      /* Fixme: Provide a way to return the used symmetric algorithm. */
      break;

    case GPGME_STATUS_DECRYPTION_OKAY:
      opd->okay = 1;
      break;

    case GPGME_STATUS_DECRYPTION_FAILED:
      opd->failed = 1;
      break;

    case GPGME_STATUS_ERROR:
      /* Note that this is an informational status code which should
         not lead to an error return unless it is something not
         related to the backend.  */
      {
	const char d_alg[] = "decrypt.algorithm";
	const char k_alg[] = "decrypt.keyusage";

	if (!strncmp (args, d_alg, sizeof (d_alg) - 1))
	  {
	    args += sizeof (d_alg) - 1;
	    while (*args == ' ')
	      args++;

	    if (gpg_err_code (atoi (args)) == GPG_ERR_UNSUPPORTED_ALGORITHM)
	      {
		char *end;

		while (*args && *args != ' ')
		  args++;
		while (*args == ' ')
		  args++;

		end = strchr (args, ' ');
		if (end)
		  *end = '\0';

		if (!(*args == '?' && *(args + 1) == '\0'))
		  {
		    opd->result.unsupported_algorithm = strdup (args);
		    if (!opd->result.unsupported_algorithm)
		      return gpg_error_from_syserror ();
		  }
	      }
	  }
	else if (!strncmp (args, k_alg, sizeof (k_alg) - 1))
	  {
	    args += sizeof (k_alg) - 1;
	    while (*args == ' ')
	      args++;

	    if (gpg_err_code (atoi (args)) == GPG_ERR_WRONG_KEY_USAGE)
	      opd->result.wrong_key_usage = 1;
	  }
      }
      break;

    case GPGME_STATUS_ENC_TO:
      err = parse_enc_to (args, opd->last_recipient_p, ctx->protocol);
      if (err)
	return err;

      opd->last_recipient_p = &(*opd->last_recipient_p)->next;
      break;

    case GPGME_STATUS_NO_SECKEY:
      {
	gpgme_recipient_t rec = opd->result.recipients;

	while (rec)
	  {
	    if (!strcmp (rec->keyid, args))
	      {
		rec->status = gpg_error (GPG_ERR_NO_SECKEY);
		break;
	      }
	    rec = rec->next;
	  }
	/* FIXME: Is this ok?  */
	if (!rec)
	  return trace_gpg_error (GPG_ERR_INV_ENGINE);
      }
      break;

    case GPGME_STATUS_PLAINTEXT:
      err = _gpgme_parse_plaintext (args, &opd->result.file_name);
      if (err)
	return err;
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
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  opd->last_recipient_p = &opd->result.recipients;
  return 0;
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
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_decrypt_start", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = decrypt_start (ctx, 0, cipher, plain);
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt (gpgme_ctx_t ctx, gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG2 (DEBUG_CTX, "gpgme_op_decrypt", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = decrypt_start (ctx, 1, cipher, plain);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}

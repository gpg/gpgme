/* decrypt.c - Decrypt function.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2017 g10 Code GmbH
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
#include <assert.h>

#include "debug.h"
#include "gpgme.h"
#include "util.h"
#include "context.h"
#include "ops.h"
#include "data.h"


typedef struct
{
  struct _gpgme_op_decrypt_result result;

  /* The error code from a FAILURE status line or 0.  */
  gpg_error_t failure_code;

  int okay;

  /* Indicates that list only mode is active.  */
  int list_only;

  /* A flag telling that the decryption failed and two optional error
   * codes to further specify the failure for public key decryption and
   * symmetric decryption.  */
  int failed;
  gpg_error_t pkdecrypt_failed;
  gpg_error_t symdecrypt_failed;

  /* At least one secret key is not available.  gpg issues NO_SECKEY
   * status lines for each key the message has been encrypted to but
   * that secret key is not available.  This can't be done for hidden
   * recipients, though.  We track it here to allow for a better error
   * message than the general DECRYPTION_FAILED. */
  int any_no_seckey;

  /* If the engine emits a DECRYPTION_INFO status and that does not
   * indicate that an integrity protection mode is active, this flag
   * is set.  */
  int not_integrity_protected;

  /* The error code from the first ERROR line.  This is in some cases
   * used to return a better matching error code to the caller.  */
  gpg_error_t first_status_error;

  /* A pointer to the next pointer of the last recipient in the list.
     This makes appending new invalid signers painless while
     preserving the order.  */
  gpgme_recipient_t *last_recipient_p;

  /* The data object serial number of the plaintext.  */
  uint64_t plaintext_dserial;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_recipient_t recipient = opd->result.recipients;

  free (opd->result.unsupported_algorithm);
  free (opd->result.file_name);
  free (opd->result.session_key);
  free (opd->result.symkey_algo);

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

  TRACE_BEG (DEBUG_CTX, "gpgme_op_decrypt_result", ctx, "");

  ctx->ignore_mdc_error = 0;  /* Always reset this flag.  */

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC ("result=(null)");
      return NULL;
    }

  /* Make sure that SYMKEY_ALGO has a value.  */
  if (!opd->result.symkey_algo)
    {
      opd->result.symkey_algo = strdup ("?.?");
      if (!opd->result.symkey_algo)
        {
          TRACE_SUC ("result=(null)");
          return NULL;
        }
    }

  if (_gpgme_debug_trace ())
    {
      gpgme_recipient_t rcp;

      if (opd->result.unsupported_algorithm)
	{
	  TRACE_LOG  ("result: unsupported_algorithm: %s",
		      opd->result.unsupported_algorithm);
	}
      if (opd->result.wrong_key_usage)
	{
	  TRACE_LOG ("result: wrong key usage");
	}
      rcp = opd->result.recipients;
      while (rcp)
	{
	  TRACE_LOG  ("result: recipient: keyid=%s, pubkey_algo=%i, "
		      "status=%s", rcp->keyid, rcp->pubkey_algo,
		      gpg_strerror (rcp->status));
	  rcp = rcp->next;
	}
      if (opd->result.file_name)
	{
	  TRACE_LOG  ("result: original file name: %s", opd->result.file_name);
	}
    }

  TRACE_SUC ("result=%p", &opd->result);
  return &opd->result;
}



/* Parse the ARGS of an error status line and record some error
 * conditions at OPD.  Returns 0 on success.  */
static gpgme_error_t
parse_status_error (char *args, op_data_t opd)
{
  gpgme_error_t err;
  char *field[3];
  int nfields;
  char *args2;

  if (!args)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  args2 = strdup (args); /* Split modifies the input string. */
  nfields = _gpgme_split_fields (args2, field, DIM (field));
  if (nfields < 1)
    {
      free (args2);
      return trace_gpg_error (GPG_ERR_INV_ENGINE); /* Required arg missing.  */
    }
  err = nfields < 2 ? 0 : atoi (field[1]);

  if (!strcmp (field[0], "decrypt.algorithm"))
    {
      if (gpg_err_code (err) == GPG_ERR_UNSUPPORTED_ALGORITHM
          && nfields > 2
          && strcmp (field[2], "?"))
        {
          opd->result.unsupported_algorithm = strdup (field[2]);
          if (!opd->result.unsupported_algorithm)
            {
              free (args2);
              return gpg_error_from_syserror ();
            }
        }
    }
  else if (!strcmp (field[0], "decrypt.keyusage"))
    {
      if (gpg_err_code (err) == GPG_ERR_WRONG_KEY_USAGE)
        opd->result.wrong_key_usage = 1;
    }
  else if (!strcmp (field[0], "pkdecrypt_failed"))
    {
      switch (gpg_err_code (err))
        {
        case GPG_ERR_CANCELED:
        case GPG_ERR_FULLY_CANCELED:
          /* It is better to return with a cancel error code than the
           * general decryption failed error code.  */
          opd->pkdecrypt_failed = gpg_err_make (gpg_err_source (err),
                                                GPG_ERR_CANCELED);
          break;

        case GPG_ERR_BAD_PASSPHRASE:
          /* A bad passphrase is severe enough that we return this
           * error code.  */
          opd->pkdecrypt_failed = err;
          break;

        default:
          /* For now all other error codes are ignored and the
           * standard DECRYPT_FAILED is returned.  */
          break;
        }
    }
  else if (!strcmp (field[0], "nomdc_with_legacy_cipher"))
    {
      opd->result.legacy_cipher_nomdc = 1;
      opd->not_integrity_protected = 1;
    }
  else if (!strcmp (field[0], "symkey_decrypt.maybe_error"))
    {
      switch (gpg_err_code (err))
        {
        case GPG_ERR_BAD_PASSPHRASE:
          /* A bad passphrase is severe enough that we return this
           * error code.  */
          opd->symdecrypt_failed = err;
          break;

        default:
          /* For now all other error codes are ignored and the
           * standard DECRYPT_FAILED is returned.  */
          break;
        }
    }
  /* Record the first error code.  */
  if (err && !opd->first_status_error)
    opd->first_status_error = err;


  free (args2);
  return 0;
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


/* Parse the ARGS of a
 *   DECRYPTION_INFO <mdc_method> <sym_algo> [<aead_algo>]
 * status.  Returns 0 on success and updates the OPD.
 */
static gpgme_error_t
parse_decryption_info (char *args, op_data_t opd, gpgme_protocol_t protocol)
{
  char *field[3];
  int nfields;
  char *args2;
  int mdc, aead_algo;
  const char *algostr, *modestr;

  if (!args)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  args2 = strdup (args); /* Split modifies the input string. */
  nfields = _gpgme_split_fields (args2, field, DIM (field));
  if (nfields < 2)
    {
      free (args2);
      return trace_gpg_error (GPG_ERR_INV_ENGINE); /* Required arg missing.  */
    }

  mdc     = atoi (field[0]);
  algostr = _gpgme_cipher_algo_name (atoi (field[1]), protocol);
  aead_algo    = nfields < 3? 0 : atoi (field[2]);
  modestr = _gpgme_cipher_mode_name (aead_algo, protocol);

  free (args2);

  free (opd->result.symkey_algo);
  if (!aead_algo && mdc != 2)
    opd->result.symkey_algo = _gpgme_strconcat (algostr, ".PGPCFB", NULL);
  else
    opd->result.symkey_algo = _gpgme_strconcat (algostr, ".", modestr, NULL);
  if (!opd->result.symkey_algo)
    return gpg_error_from_syserror ();

  if (!mdc && !aead_algo)
    opd->not_integrity_protected = 1;

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
      if (!opd->failure_code
          || gpg_err_code (opd->failure_code) == GPG_ERR_GENERAL)
        opd->failure_code = _gpgme_parse_failure (args);
      break;

    case GPGME_STATUS_EOF:
      /* We force an encryption failure if we know that integrity
       * protection is missing.  For modern version of gpg using
       * modern cipher algorithms this is not required because gpg
       * will issue a failure anyway.  However older gpg versions emit
       * only a warning.
       * Fixme: These error values should probably be attributed to
       * the underlying crypto engine (as error source).  */
      if (opd->failed)
        {
          /* This comes from a specialized ERROR status line.  */
          if (opd->pkdecrypt_failed)
            return opd->pkdecrypt_failed;
          if (opd->symdecrypt_failed)
            return opd->symdecrypt_failed;

          /* For an integrity failure return just DECRYPTION_FAILED;
           * the actual cause can be taken from an already set
           * decryption result flag.  */
          if ((opd->not_integrity_protected && !ctx->ignore_mdc_error))
            return gpg_error (GPG_ERR_DECRYPT_FAILED);

          /* If we have any other ERROR code we prefer that over
           * NO_SECKEY because it is probably the better matching
           * code.  For example a garbled message with multiple
           * plaintext will return BAD_DATA here but may also have
           * indicated a NO_SECKEY.  */
          if (opd->first_status_error)
            return opd->first_status_error;

          /* No secret key is pretty common reason.  */
          if (opd->any_no_seckey)
            return gpg_error (GPG_ERR_NO_SECKEY);

          /* Generic decryption failed error code.  */
          return gpg_error (GPG_ERR_DECRYPT_FAILED);
        }
      else if (!opd->okay && !opd->list_only)
        {
          /* No data was found.  */
          return gpg_error (GPG_ERR_NO_DATA);
        }
      else if (opd->failure_code)
        {
          /* The engine returned failure code at program exit.  */
          return opd->failure_code;
        }
      break;

    case GPGME_STATUS_DECRYPTION_INFO:
      err = parse_decryption_info (args, opd, ctx->protocol);
      if (err)
	return err;
      break;

    case GPGME_STATUS_DECRYPTION_OKAY:
      opd->okay = 1;
      break;

    case GPGME_STATUS_DECRYPTION_FAILED:
      opd->failed = 1;
      /* Tell the data object that it shall not return any data.  We
       * use the serial number because the data object may be owned by
       * another thread.  We also don't check for an error because it
       * is possible that the data object has already been destroyed
       * and we are then not interested in returning an error.  */
      if (!ctx->ignore_mdc_error)
        _gpgme_data_set_prop (NULL, opd->plaintext_dserial,
                              DATA_PROP_BLANKOUT, 1);
      break;

    case GPGME_STATUS_ERROR:
      /* Note that this is an informational status code which should
       * not lead to an error return unless it is something not
       * related to the backend.  However, it is used to return a
       * better matching final error code.  */
      err = parse_status_error (args, opd);
      if (err)
        return err;
      break;

    case GPGME_STATUS_ENC_TO:
      err = parse_enc_to (args, opd->last_recipient_p, ctx->protocol);
      if (err)
	return err;

      opd->last_recipient_p = &(*opd->last_recipient_p)->next;
      break;

    case GPGME_STATUS_SESSION_KEY:
      if (opd->result.session_key)
        free (opd->result.session_key);
      opd->result.session_key = strdup(args);
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
        opd->any_no_seckey = 1;
      }
      break;

    case GPGME_STATUS_PLAINTEXT:
      {
        int mime = 0;
        err = _gpgme_parse_plaintext (args, &opd->result.file_name, &mime);
        if (err)
          return err;
        opd->result.is_mime = !!mime;
      }
      break;

    case GPGME_STATUS_INQUIRE_MAXLEN:
      if (ctx->status_cb && !ctx->full_status)
        {
          err = ctx->status_cb (ctx->status_cb_value, "INQUIRE_MAXLEN", args);
          if (err)
            return err;
        }
      break;

    case GPGME_STATUS_DECRYPTION_COMPLIANCE_MODE:
      PARSE_COMPLIANCE_FLAGS (args, &opd->result);
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
_gpgme_op_decrypt_init_result (gpgme_ctx_t ctx, gpgme_data_t plaintext,
                               gpgme_decrypt_flags_t flags)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_DECRYPT, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  opd->list_only = !!(flags & GPGME_DECRYPT_LISTONLY);
  opd->last_recipient_p = &opd->result.recipients;
  opd->plaintext_dserial = _gpgme_data_get_dserial (plaintext);
  return 0;
}


gpgme_error_t
_gpgme_decrypt_start (gpgme_ctx_t ctx, int synchronous,
                      gpgme_decrypt_flags_t flags,
                      gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err;

  assert (!(flags & GPGME_DECRYPT_VERIFY));

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_decrypt_init_result (ctx, plain, flags);
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
	(ctx->engine, _gpgme_passphrase_command_handler, ctx);
      if (err)
	return err;
    }

  _gpgme_engine_set_status_handler (ctx->engine, decrypt_status_handler, ctx);

  return _gpgme_engine_op_decrypt (ctx->engine,
                                   flags,
                                   cipher, plain,
                                   ctx->export_session_keys,
                                   ctx->override_session_key,
                                   ctx->auto_key_retrieve);
}


gpgme_error_t
gpgme_op_decrypt_start (gpgme_ctx_t ctx, gpgme_data_t cipher,
			gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt_start", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_decrypt_start (ctx, 0, 0, cipher, plain);
  return TRACE_ERR (err);
}


/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t
gpgme_op_decrypt (gpgme_ctx_t ctx, gpgme_data_t cipher, gpgme_data_t plain)
{
  gpgme_error_t err;

  TRACE_BEG  (DEBUG_CTX, "gpgme_op_decrypt", ctx,
	      "cipher=%p, plain=%p", cipher, plain);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_decrypt_start (ctx, 1, 0, cipher, plain);
  if (!err)
    err = _gpgme_wait_one (ctx);
  ctx->ignore_mdc_error = 0;  /* Always reset.  */
  return TRACE_ERR (err);
}

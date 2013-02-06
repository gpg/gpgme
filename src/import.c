/* import.c - Import a key.
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
#include <errno.h>
#include <string.h>

#include "gpgme.h"
#include "debug.h"
#include "context.h"
#include "ops.h"
#include "util.h"


typedef struct
{
  struct _gpgme_op_import_result result;

  /* A pointer to the next pointer of the last import status in the
     list.  This makes appending new imports painless while preserving
     the order.  */
  gpgme_import_status_t *lastp;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  gpgme_import_status_t import = opd->result.imports;

  while (import)
    {
      gpgme_import_status_t next = import->next;
      free (import->fpr);
      free (import);
      import = next;
    }
}


gpgme_import_result_t
gpgme_op_import_result (gpgme_ctx_t ctx)
{
  void *hook;
  op_data_t opd;
  gpgme_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_import_result", ctx);

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, &hook, -1, NULL);
  opd = hook;
  if (err || !opd)
    {
      TRACE_SUC0 ("result=(null)");
      return NULL;
    }


  if (_gpgme_debug_trace ())
    {
      gpgme_import_status_t impstat;
      int i;

      TRACE_LOG5 ("%i considered, %i no UID, %i imported, %i imported RSA, "
		  "%i unchanged", opd->result.considered,
		  opd->result.no_user_id, opd->result.imported,
		  opd->result.imported_rsa, opd->result.unchanged);
      TRACE_LOG4 ("%i new UIDs, %i new sub keys, %i new signatures, "
		  "%i new revocations", opd->result.new_user_ids,
		  opd->result.new_sub_keys, opd->result.new_signatures,
		  opd->result.new_revocations);
      TRACE_LOG3 ("%i secret keys, %i imported, %i unchanged",
		  opd->result.secret_read, opd->result.secret_imported,
		  opd->result.secret_unchanged);
      TRACE_LOG2 ("%i skipped new keys, %i not imported",
		  opd->result.skipped_new_keys, opd->result.not_imported);

      impstat = opd->result.imports;
      i = 0;
      while (impstat)
	{
	  TRACE_LOG4 ("import[%i] for %s = 0x%x (%s)",
		      i, impstat->fpr, impstat->status, impstat->result);
	  impstat = impstat->next;
	  i++;
	}
    }

  TRACE_SUC1 ("result=%p", &opd->result);
  return &opd->result;
}


static gpgme_error_t
parse_import (char *args, gpgme_import_status_t *import_status, int problem)
{
  gpgme_import_status_t import;
  char *tail;
  long int nr;

  import = malloc (sizeof (*import));
  if (!import)
    return gpg_error_from_syserror ();
  import->next = NULL;

  gpg_err_set_errno (0);
  nr = strtol (args, &tail, 0);
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (import);
      return trace_gpg_error (GPG_ERR_INV_ENGINE);
    }
  args = tail;

  if (problem)
    {
      switch (nr)
	{
	case 0:
	case 4:
	default:
	  import->result = gpg_error (GPG_ERR_GENERAL);
	  break;

	case 1:
	  import->result = gpg_error (GPG_ERR_BAD_CERT);
	  break;

	case 2:
	  import->result = gpg_error (GPG_ERR_MISSING_ISSUER_CERT);
	  break;

	case 3:
	  import->result = gpg_error (GPG_ERR_BAD_CERT_CHAIN);
	  break;
	}
      import->status = 0;
    }
  else
    {
      import->result = gpg_error (GPG_ERR_NO_ERROR);
      import->status = nr;
    }

  while (*args == ' ')
    args++;
  tail = strchr (args, ' ');
  if (tail)
    *tail = '\0';

  import->fpr = strdup (args);
  if (!import->fpr)
    {
      free (import);
      return gpg_error_from_syserror ();
    }

  *import_status = import;
  return 0;
}



gpgme_error_t
parse_import_res (char *args, gpgme_import_result_t result)
{
  char *tail;

  gpg_err_set_errno (0);

#define PARSE_NEXT(x)					\
  (x) = strtol (args, &tail, 0);			\
  if (errno || args == tail || *tail != ' ')		\
    /* The crypto backend does not behave.  */		\
    return trace_gpg_error (GPG_ERR_INV_ENGINE);        \
  args = tail;

  PARSE_NEXT (result->considered);
  PARSE_NEXT (result->no_user_id);
  PARSE_NEXT (result->imported);
  PARSE_NEXT (result->imported_rsa);
  PARSE_NEXT (result->unchanged);
  PARSE_NEXT (result->new_user_ids);
  PARSE_NEXT (result->new_sub_keys);
  PARSE_NEXT (result->new_signatures);
  PARSE_NEXT (result->new_revocations);
  PARSE_NEXT (result->secret_read);
  PARSE_NEXT (result->secret_imported);
  PARSE_NEXT (result->secret_unchanged);
  PARSE_NEXT (result->skipped_new_keys);
  PARSE_NEXT (result->not_imported);

  return 0;
}


static gpgme_error_t
import_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, &hook, -1, NULL);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_IMPORT_OK:
    case GPGME_STATUS_IMPORT_PROBLEM:
      err = parse_import (args, opd->lastp,
			  code == GPGME_STATUS_IMPORT_OK ? 0 : 1);
      if (err)
	return err;

      opd->lastp = &(*opd->lastp)->next;
      break;

    case GPGME_STATUS_IMPORT_RES:
      err = parse_import_res (args, &opd->result);
      break;

    default:
      break;
    }
  return 0;
}


static gpgme_error_t
_gpgme_op_import_start (gpgme_ctx_t ctx, int synchronous, gpgme_data_t keydata)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;
  opd->lastp = &opd->result.imports;

  if (!keydata)
    return gpg_error (GPG_ERR_NO_DATA);

  _gpgme_engine_set_status_handler (ctx->engine, import_status_handler, ctx);

  return _gpgme_engine_op_import (ctx->engine, keydata, NULL);
}


gpgme_error_t
gpgme_op_import_start (gpgme_ctx_t ctx, gpgme_data_t keydata)
{
  gpg_error_t err;

  TRACE_BEG1 (DEBUG_CTX, "gpgme_op_import_start", ctx,
	      "keydata=%p", keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_op_import_start (ctx, 0, keydata);
  return TRACE_ERR (err);
}


/* Import the key in KEYDATA into the keyring.  */
gpgme_error_t
gpgme_op_import (gpgme_ctx_t ctx, gpgme_data_t keydata)
{
  gpgme_error_t err;

  TRACE_BEG1 (DEBUG_CTX, "gpgme_op_import", ctx,
	      "keydata=%p", keydata);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_op_import_start (ctx, 1, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}



static gpgme_error_t
_gpgme_op_import_keys_start (gpgme_ctx_t ctx, int synchronous,
                             gpgme_key_t *keys)
{
  gpgme_error_t err;
  void *hook;
  op_data_t opd;
  int idx, firstidx, nkeys;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;
  opd->lastp = &opd->result.imports;

  if (!keys)
    return gpg_error (GPG_ERR_NO_DATA);

  for (idx=nkeys=0, firstidx=-1; keys[idx]; idx++)
    {
      /* We only consider keys of the current protocol.  */
      if (keys[idx]->protocol != ctx->protocol)
        continue;
      if (firstidx == -1)
        firstidx = idx;
      /* If a key has been found using a different key listing mode,
         we bail out.  This makes the processing easier.  Fixme: To
         allow a mix of keys we would need to sort them by key listing
         mode and start two import operations one after the other.  */
      if (keys[idx]->keylist_mode != keys[firstidx]->keylist_mode)
        return gpg_error (GPG_ERR_CONFLICT);
      nkeys++;
    }
  if (!nkeys)
    return gpg_error (GPG_ERR_NO_DATA);

  _gpgme_engine_set_status_handler (ctx->engine, import_status_handler, ctx);

  return _gpgme_engine_op_import (ctx->engine, NULL, keys);
}


/* Asynchronous version of gpgme_op_import_key.  */
gpgme_error_t
gpgme_op_import_keys_start (gpgme_ctx_t ctx, gpgme_key_t *keys)
{
  gpg_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_import_keys_start", ctx);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && keys)
    {
      int i = 0;

      while (keys[i])
	{
	  TRACE_LOG3 ("keys[%i] = %p (%s)", i, keys[i],
		      (keys[i]->subkeys && keys[i]->subkeys->fpr) ?
		      keys[i]->subkeys->fpr : "invalid");
	  i++;
	}
    }

  err = _gpgme_op_import_keys_start (ctx, 0, keys);
  return TRACE_ERR (err);
}


/* Import the keys from the array KEYS into the keyring.  This
   function allows to move a key from one engine to another as long as
   they are compatible.  In particular it is used to actually import
   keys retrieved from an external source (i.e. using
   GPGME_KEYLIST_MODE_EXTERN).  It replaces the old workaround of
   exporting and then importing a key as used to make an X.509 key
   permanent.  This function automagically does the right thing.

   KEYS is a NULL terminated array of gpgme key objects.  The result
   is the usual import result structure.  Only keys matching the
   current protocol are imported; other keys are ignored.  */
gpgme_error_t
gpgme_op_import_keys (gpgme_ctx_t ctx, gpgme_key_t *keys)
{
  gpgme_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_op_import_keys", ctx);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (_gpgme_debug_trace () && keys)
    {
      int i = 0;

      while (keys[i])
	{
	  TRACE_LOG3 ("keys[%i] = %p (%s)", i, keys[i],
		      (keys[i]->subkeys && keys[i]->subkeys->fpr) ?
		      keys[i]->subkeys->fpr : "invalid");
	  i++;
	}
    }

  err = _gpgme_op_import_keys_start (ctx, 1, keys);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return TRACE_ERR (err);
}


/* Deprecated interface.  */
gpgme_error_t
gpgme_op_import_ext (gpgme_ctx_t ctx, gpgme_data_t keydata, int *nr)
{
  gpgme_error_t err = gpgme_op_import (ctx, keydata);
  if (!err && nr)
    {
      gpgme_import_result_t result = gpgme_op_import_result (ctx);
      *nr = result->considered;
    }
  return err;
}

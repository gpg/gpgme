/* import.c - Import a key.
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
#include <errno.h>
#include <string.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  struct _gpgme_op_import_result result;

  /* A pointer to the next pointer of the last import status in the
     list.  This makes appending new imports painless while preserving
     the order.  */
  GpgmeImportStatus *lastp;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;
  GpgmeImportStatus import = opd->result.imports;

  while (import)
    {
      GpgmeImportStatus next = import->next;
      free (import->fpr);
      free (import);
      import = next;
    }
}


GpgmeImportResult
gpgme_op_import_result (GpgmeCtx ctx)
{
  op_data_t opd;
  GpgmeError err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, (void **) &opd, -1, NULL);
  if (err || !opd)
    return NULL;

  return &opd->result;
}


static GpgmeError
parse_import (char *args, GpgmeImportStatus *import_status, int problem)
{
  GpgmeImportStatus import;
  char *tail;
  long int nr;

  import = malloc (sizeof (*import));
  if (!import)
    return GPGME_Out_Of_Core;
  import->next = NULL;

  errno = 0;
  nr = strtol (args, &tail, 0);
  if (errno || args == tail || *tail != ' ')
    {
      /* The crypto backend does not behave.  */
      free (import);
      return GPGME_General_Error;
    }
  args = tail;

  if (problem)
    {
      switch (nr)
	{
	case 0:
	case 4:
	default:
	  import->result = GPGME_Unknown_Reason;
	  break;

	case 1:
	  import->result = GPGME_Invalid_Key;
	  break;

	case 2:
	  import->result = GPGME_Issuer_Missing;
	  break;

	case 3:
	  import->result = GPGME_Chain_Too_Long;
	  break;
	}
      import->status = 0;
    }
  else
    {
      import->result = GPGME_No_Error;
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
      return GPGME_Out_Of_Core;
    }

  *import_status = import;
  return 0;
}



GpgmeError
parse_import_res (char *args, GpgmeImportResult result)
{
  char *tail;

  errno = 0;

#define PARSE_NEXT(x)					\
  (x) = strtol (args, &tail, 0);			\
  if (errno || args == tail || *tail != ' ')		\
    /* The crypto backend does not behave.  */		\
    return GPGME_General_Error;				\
  args = tail;

  PARSE_NEXT (result->considered);
  PARSE_NEXT (result->no_user_id);
  PARSE_NEXT (result->imported);
  PARSE_NEXT (result->imported_rsa);
  PARSE_NEXT (result->new_user_ids);
  PARSE_NEXT (result->new_sub_keys);
  PARSE_NEXT (result->new_signatures);
  PARSE_NEXT (result->new_revocations);
  PARSE_NEXT (result->secret_read);
  PARSE_NEXT (result->secret_imported);
  PARSE_NEXT (result->secret_unchanged);
  PARSE_NEXT (result->not_imported);

  return 0;
}


static GpgmeError
import_status_handler (void *priv, GpgmeStatusCode code, char *args)
{
  GpgmeCtx ctx = (GpgmeCtx) priv;
  GpgmeError err;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, (void **) &opd,
			       -1, NULL);
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


static GpgmeError
_gpgme_op_import_start (GpgmeCtx ctx, int synchronous, GpgmeData keydata)
{
  GpgmeError err;
  op_data_t opd;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    return err;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, (void **) &opd,
			       sizeof (*opd), release_op_data);
  if (err)
    return err;
  opd->lastp = &opd->result.imports;

  if (!keydata)
    return GPGME_No_Data;

  _gpgme_engine_set_status_handler (ctx->engine, import_status_handler, ctx);

  return _gpgme_engine_op_import (ctx->engine, keydata);
}


GpgmeError
gpgme_op_import_start (GpgmeCtx ctx, GpgmeData keydata)
{
  return _gpgme_op_import_start (ctx, 0, keydata);
}


/* Import the key in KEYDATA into the keyring.  */
GpgmeError
gpgme_op_import (GpgmeCtx ctx, GpgmeData keydata)
{
  GpgmeError err = _gpgme_op_import_start (ctx, 1, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  return err;
}


GpgmeError
gpgme_op_import_ext (GpgmeCtx ctx, GpgmeData keydata, int *nr)
{
  GpgmeError err = gpgme_op_import (ctx, keydata);
  if (!err && nr)
    {
      GpgmeImportResult result = gpgme_op_import_result (ctx);
      *nr = result->considered;
    }
  return err;
}

/* passphrase.c - Passphrase callback.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  int no_passphrase;
  char *uid_hint;
  char *passphrase_info;
  int bad_passphrase;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;

  if (opd->passphrase_info)
    free (opd->passphrase_info);
  if (opd->uid_hint)
    free (opd->uid_hint);
}


gpgme_error_t
_gpgme_passphrase_status_handler (void *priv, gpgme_status_code_t code,
				  char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  if (!ctx->passphrase_cb)
    return 0;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_USERID_HINT:
      if (opd->uid_hint)
	free (opd->uid_hint);
      if (!(opd->uid_hint = strdup (args)))
      return gpg_error_from_errno (errno);
      break;

    case GPGME_STATUS_BAD_PASSPHRASE:
      opd->bad_passphrase++;
      opd->no_passphrase = 0;
      break;

    case GPGME_STATUS_GOOD_PASSPHRASE:
      opd->bad_passphrase = 0;
      opd->no_passphrase = 0;
      break;

    case GPGME_STATUS_NEED_PASSPHRASE:
    case GPGME_STATUS_NEED_PASSPHRASE_SYM:
      if (opd->passphrase_info)
	free (opd->passphrase_info);
      opd->passphrase_info = strdup (args);
      if (!opd->passphrase_info)
	return gpg_error_from_errno (errno);
      break;

    case GPGME_STATUS_MISSING_PASSPHRASE:
      opd->no_passphrase = 1;
      break;

    case GPGME_STATUS_EOF:
      if (opd->no_passphrase || opd->bad_passphrase)
	return gpg_error (GPG_ERR_BAD_PASSPHRASE);
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


gpgme_error_t
_gpgme_passphrase_command_handler_internal (void *priv,
					    gpgme_status_code_t code,
					    const char *key, int fd,
					    int *processed)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  assert (ctx->passphrase_cb);

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  if (code == GPGME_STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter"))
    {
      if (processed)
	*processed = 1;

      err = ctx->passphrase_cb (ctx->passphrase_cb_value,
				opd->uid_hint, opd->passphrase_info,
				opd->bad_passphrase, fd);

      /* Reset bad passphrase flag, in case it is correct now.  */
      opd->bad_passphrase = 0;

      return err;
    }

  return 0;
}


gpgme_error_t
_gpgme_passphrase_command_handler (void *priv, gpgme_status_code_t code,
				   const char *key, int fd)
{
  return _gpgme_passphrase_command_handler_internal (priv, code, key, fd,
						     NULL);
}

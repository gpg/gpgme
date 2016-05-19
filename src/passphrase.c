/* passphrase.c - Passphrase callback.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "gpgme.h"
#include "context.h"
#include "ops.h"
#include "util.h"
#include "debug.h"


typedef struct
{
  int no_passphrase;
  char *uid_hint;
  char *passphrase_info;
  int bad_passphrase;
  char *maxlen;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;

  if (opd->passphrase_info)
    free (opd->passphrase_info);
  if (opd->uid_hint)
    free (opd->uid_hint);
  free (opd->maxlen);
}


gpgme_error_t
_gpgme_passphrase_status_handler (void *priv, gpgme_status_code_t code,
				  char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  void *hook;
  op_data_t opd;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, &hook,
			       sizeof (*opd), release_op_data);
  opd = hook;
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_INQUIRE_MAXLEN:
      free (opd->maxlen);
      if (!(opd->maxlen = strdup (args)))
        return gpg_error_from_syserror ();
      break;
    case GPGME_STATUS_USERID_HINT:
      if (opd->uid_hint)
	free (opd->uid_hint);
      if (!(opd->uid_hint = strdup (args)))
        return gpg_error_from_syserror ();
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
    case GPGME_STATUS_NEED_PASSPHRASE_PIN:
      if (opd->passphrase_info)
	free (opd->passphrase_info);
      opd->passphrase_info = strdup (args);
      if (!opd->passphrase_info)
	return gpg_error_from_syserror ();
      break;

    case GPGME_STATUS_MISSING_PASSPHRASE:
      opd->no_passphrase = 1;
      break;

    case GPGME_STATUS_EOF:
      if (opd->no_passphrase || opd->bad_passphrase)
	return gpg_error (GPG_ERR_BAD_PASSPHRASE);
      break;

    case GPGME_STATUS_ERROR:
      /* We abuse this status handler to forward ERROR status codes to
         the caller.  */
      if (ctx->status_cb && !ctx->full_status)
        {
          err = ctx->status_cb (ctx->status_cb_value, "ERROR", args);
          if (err)
            return err;
        }
      break;

    case GPGME_STATUS_FAILURE:
      /* We abuse this status handler to forward FAILURE status codes
         to the caller.  */
      if (ctx->status_cb && !ctx->full_status)
        {
          err = ctx->status_cb (ctx->status_cb_value, "FAILURE", args);
          if (err)
            return err;
        }
      break;


    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


gpgme_error_t
_gpgme_passphrase_command_handler (void *priv, gpgme_status_code_t code,
				   const char *key, int fd, int *processed)
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

  if (code == GPGME_STATUS_GET_HIDDEN
      && (!strcmp (key, "passphrase.enter")
          || !strcmp (key, "passphrase.pin.ask")))
    {
      if (processed)
	*processed = 1;

      /* Fake a status line to to convey the MAXLEN info.  */
      if (ctx->status_cb && opd->maxlen)
        err = ctx->status_cb (ctx->status_cb_value, "INQUIRE_MAXLEN",
                              opd->maxlen);

      if (!err)
        err = ctx->passphrase_cb (ctx->passphrase_cb_value,
                                  opd->uid_hint, opd->passphrase_info,
                                  opd->bad_passphrase, fd);

      /* Reset bad passphrase flag, in case it is correct now.  */
      opd->bad_passphrase = 0;

      return err;
    }

  return 0;
}

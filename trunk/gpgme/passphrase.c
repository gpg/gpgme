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

#include "gpgme.h"
#include "context.h"
#include "ops.h"


typedef struct
{
  int no_passphrase;
  void *last_pw_handle;
  char *userid_hint;
  char *passphrase_info;
  int bad_passphrase;
} *op_data_t;


static void
release_op_data (void *hook)
{
  op_data_t opd = (op_data_t) hook;

  free (opd->passphrase_info);
  free (opd->userid_hint);
}


gpgme_error_t
_gpgme_passphrase_status_handler (void *priv, gpgme_status_code_t code, char *args)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  op_data_t opd;

  if (!ctx->passphrase_cb)
    return 0;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, (void **) &opd,
			       sizeof (*opd), release_op_data);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_USERID_HINT:
      if (opd->userid_hint)
	free (opd->userid_hint);
      if (!(opd->userid_hint = strdup (args)))
	return GPGME_Out_Of_Core;
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
	return GPGME_Out_Of_Core;
      break;

    case GPGME_STATUS_MISSING_PASSPHRASE:
      opd->no_passphrase = 1;
      break;

    case GPGME_STATUS_EOF:
      if (opd->no_passphrase || opd->bad_passphrase)
	return GPGME_Bad_Passphrase;
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


gpgme_error_t
_gpgme_passphrase_command_handler (void *priv, gpgme_status_code_t code,
				   const char *key, const char **result)
{
  gpgme_ctx_t ctx = (gpgme_ctx_t) priv;
  gpgme_error_t err;
  op_data_t opd;

  if (!ctx->passphrase_cb)
    return 0;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, (void **) &opd,
			       sizeof (*opd), release_op_data);
  if (err)
    return err;

  if (!code)
    {
      /* We have been called for cleanup.  */
      if (ctx->passphrase_cb)
	/* FIXME: Take the key in account.  */
	err = ctx->passphrase_cb (ctx->passphrase_cb_value, NULL,
				  &opd->last_pw_handle, NULL);
      *result = NULL;
      return err;
    }

  if (!key || !ctx->passphrase_cb)
    {
      *result = NULL;
      return 0;
    }
    
  if (code == GPGME_STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter"))
    {
      const char *userid_hint = opd->userid_hint;
      const char *passphrase_info = opd->passphrase_info;
      int bad_passphrase = opd->bad_passphrase;
      char *buf;

      opd->bad_passphrase = 0;
      if (!userid_hint)
	userid_hint = "[User ID hint missing]";
      if (!passphrase_info)
	passphrase_info = "[passphrase info missing]";
      buf = malloc (20 + strlen (userid_hint)
		    + strlen (passphrase_info) + 3);
      if (!buf)
	return GPGME_Out_Of_Core;
      sprintf (buf, "%s\n%s\n%s",
	       bad_passphrase ? "TRY_AGAIN":"ENTER",
	       userid_hint, passphrase_info);

      err = ctx->passphrase_cb (ctx->passphrase_cb_value, buf,
				&opd->last_pw_handle, result);
      free (buf);
      return err;
    }

  *result = NULL;
  return 0;
}

/* passphrase.c -  passphrase functions
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

#include "util.h"
#include "context.h"
#include "ops.h"
#include "debug.h"


struct passphrase_result
{
  int no_passphrase;
  void *last_pw_handle;
  char *userid_hint;
  char *passphrase_info;
  int bad_passphrase;
};
typedef struct passphrase_result *PassphraseResult;

static void
release_passphrase_result (void *hook)
{
  PassphraseResult result = (PassphraseResult) hook;

  free (result->passphrase_info);
  free (result->userid_hint);
}


GpgmeError
_gpgme_passphrase_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GpgmeError err;
  PassphraseResult result;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, (void **) &result,
			       sizeof (*result), release_passphrase_result);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_USERID_HINT:
      free (result->userid_hint);
      if (!(result->userid_hint = strdup (args)))
	return GPGME_Out_Of_Core;
      break;

    case GPGME_STATUS_BAD_PASSPHRASE:
      result->bad_passphrase++;
      result->no_passphrase = 0;
      break;

    case GPGME_STATUS_GOOD_PASSPHRASE:
      result->bad_passphrase = 0;
      result->no_passphrase = 0;
      break;

    case GPGME_STATUS_NEED_PASSPHRASE:
    case GPGME_STATUS_NEED_PASSPHRASE_SYM:
      free (result->passphrase_info);
      result->passphrase_info = strdup (args);
      if (!result->passphrase_info)
	return GPGME_Out_Of_Core;
      break;

    case GPGME_STATUS_MISSING_PASSPHRASE:
      DEBUG0 ("missing passphrase - stop\n");;
      result->no_passphrase = 1;
      break;

    case GPGME_STATUS_EOF:
      if (result->no_passphrase
	  || result->bad_passphrase)
	return GPGME_No_Passphrase;
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
  return 0;
}


GpgmeError
_gpgme_passphrase_command_handler (void *opaque, GpgmeStatusCode code,
				   const char *key, const char **result_r)
{
  GpgmeCtx ctx = opaque;
  GpgmeError err;
  PassphraseResult result;

  err = _gpgme_op_data_lookup (ctx, OPDATA_PASSPHRASE, (void **) &result,
			       sizeof (*result), release_passphrase_result);
  if (err)
    return err;

  if (!code)
    {
      /* We have been called for cleanup.  */
      if (ctx->passphrase_cb)
	{ 
	  /* Fixme: Take the key in account.  */
	  ctx->passphrase_cb (ctx->passphrase_cb_value, NULL, 
			      &result->last_pw_handle);
        }
      *result_r = NULL;
      return 0;
    }

  if (!key || !ctx->passphrase_cb)
    {
      *result_r = NULL;
      return 0;
    }
    
  if (code == GPGME_STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter"))
    {
      const char *userid_hint = result->userid_hint;
      const char *passphrase_info = result->passphrase_info;
      int bad_passphrase = result->bad_passphrase;
      char *buf;

      result->bad_passphrase = 0;
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

      *result_r = ctx->passphrase_cb (ctx->passphrase_cb_value, buf,
				      &result->last_pw_handle);
      free (buf);
      return 0;
    }

  *result_r = NULL;
  return 0;
}


GpgmeError
_gpgme_passphrase_start (GpgmeCtx ctx)
{
  GpgmeError err = 0;

  if (ctx->passphrase_cb)
    err = _gpgme_engine_set_command_handler (ctx->engine,
					     _gpgme_passphrase_command_handler,
					     ctx, NULL);
  return err;
}

/* passphrase.c -  passphrase functions
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

struct passphrase_result_s
{
  int no_passphrase;
  void *last_pw_handle;
  char *userid_hint;
  char *passphrase_info;
  int bad_passphrase;
};

void
_gpgme_release_passphrase_result (PassphraseResult result)
{
  if (!result)
    return;
  xfree (result->passphrase_info);
  xfree (result->userid_hint);
  xfree (result);
}

void
_gpgme_passphrase_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  if (ctx->out_of_core)
    return;

  if (!ctx->result.passphrase)
    {
      ctx->result.passphrase = xtrycalloc (1, sizeof *ctx->result.passphrase);
      if (!ctx->result.passphrase)
	{
	  ctx->out_of_core = 1;
	  return;
	}
    }

  switch (code)
    {
    case STATUS_USERID_HINT:
      xfree (ctx->result.passphrase->userid_hint);
      if (!(ctx->result.passphrase->userid_hint = xtrystrdup (args)) )
	ctx->out_of_core = 1;
      break;

    case STATUS_BAD_PASSPHRASE:
      ctx->result.passphrase->bad_passphrase++;
      break;

    case STATUS_GOOD_PASSPHRASE:
      ctx->result.passphrase->bad_passphrase = 0;
      break;

    case STATUS_NEED_PASSPHRASE:
    case STATUS_NEED_PASSPHRASE_SYM:
      xfree (ctx->result.passphrase->passphrase_info);
      ctx->result.passphrase->passphrase_info = xtrystrdup (args);
      if (!ctx->result.passphrase->passphrase_info)
	ctx->out_of_core = 1;
      break;

    case STATUS_MISSING_PASSPHRASE:
      DEBUG0 ("missing passphrase - stop\n");;
      ctx->result.passphrase->no_passphrase = 1;
      break;

    default:
      /* Ignore all other codes.  */
      break;
    }
}

static const char *
command_handler (void *opaque, GpgStatusCode code, const char *key)
{
  GpgmeCtx ctx = opaque;

  if (!ctx->result.passphrase)
    {
      ctx->result.passphrase = xtrycalloc (1, sizeof *ctx->result.passphrase);
      if (!ctx->result.passphrase)
	{
	  ctx->out_of_core = 1;
	  return NULL;
	}
    }

  if (!code)
    {
      /* We have been called for cleanup.  */
      if (ctx->passphrase_cb)
	{ 
	  /* Fixme: Take the key in account.  */
	  ctx->passphrase_cb (ctx->passphrase_cb_value, NULL, 
			      &ctx->result.passphrase->last_pw_handle);
        }
      return NULL;
    }

  if (!key || !ctx->passphrase_cb)
    return NULL;
    
  if (code == STATUS_GET_HIDDEN && !strcmp (key, "passphrase.enter"))
    {
      const char *userid_hint = ctx->result.passphrase->userid_hint;
      const char *passphrase_info = ctx->result.passphrase->passphrase_info;
      int bad_passphrase = ctx->result.passphrase->bad_passphrase;
      char *buf;
      const char *s;

      ctx->result.passphrase->bad_passphrase = 0;
      if (!userid_hint)
	userid_hint = "[User ID hint missing]";
      if (!passphrase_info)
	passphrase_info = "[passphrase info missing]";
      buf = xtrymalloc (20 + strlen (userid_hint)
			+ strlen (passphrase_info) + 3);
      if (!buf)
	{
	  ctx->out_of_core = 1;
	  return NULL;
        }
      sprintf (buf, "%s\n%s\n%s",
	       bad_passphrase ? "TRY_AGAIN":"ENTER",
	       userid_hint, passphrase_info);

      s = ctx->passphrase_cb (ctx->passphrase_cb_value,
			      buf, &ctx->result.passphrase->last_pw_handle);
      xfree (buf);
      return s;
    }

    return NULL;
}

GpgmeError
_gpgme_passphrase_start (GpgmeCtx ctx)
{
  GpgmeError err = 0;

  if (ctx->passphrase_cb)
    err = _gpgme_gpg_set_command_handler (ctx->gpg, command_handler, ctx);
  return err;
}

GpgmeError
_gpgme_passphrase_result (GpgmeCtx ctx)
{
  GpgmeError err = 0;

  if (!ctx->result.passphrase)
    err = mk_error (General_Error);
  else if (ctx->out_of_core)
    err = mk_error (Out_Of_Core);
  else if (ctx->result.passphrase->no_passphrase)
    err = mk_error (No_Passphrase);
  return err;
}

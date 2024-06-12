/* gpgme.c - GnuPG Made Easy.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2012,
 *               2014, 2015 g10 Code GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "debug.h"
#include "priv-io.h"
#include "sys-util.h"
#include "mbox-util.h"


/* The default locale.  */
DEFINE_STATIC_LOCK (def_lc_lock);
static char *def_lc_ctype;
static char *def_lc_messages;


gpgme_error_t _gpgme_selftest = GPG_ERR_NOT_OPERATIONAL;

/* Protects all reference counters in result structures.  All other
   accesses to a result structure are read only.  */
DEFINE_STATIC_LOCK (result_ref_lock);


/* Set the global flag NAME to VALUE.  Return 0 on success.  Note that
   this function does not use gpgme_error and thus a non-zero return
   value merely means "error".  Certain flags may be set before
   gpgme_check_version is called.  See the manual for a description of
   supported flags.  The caller must assure that this function is
   called only by one thread at a time.  */
int
gpgme_set_global_flag (const char *name, const char *value)
{
  if (!name || !value)
    return -1;
  else if (!strcmp (name, "debug"))
    return _gpgme_debug_set_debug_envvar (value);
  else if (!strcmp (name, "disable-gpgconf"))
    {
      _gpgme_dirinfo_disable_gpgconf ();
      return 0;
    }
  else if (!strcmp (name, "require-gnupg"))
    return _gpgme_set_engine_minimal_version (value);
  else if (!strcmp (name, "gpgconf-name"))
    return _gpgme_set_default_gpgconf_name (value);
  else if (!strcmp (name, "gpg-name"))
    return _gpgme_set_default_gpg_name (value);
  else if (!strcmp (name, "inst-type"))
    {
      _gpgme_set_get_inst_type (value);
      return 0;
    }
  else if (!strcmp (name, "w32-inst-dir"))
    return _gpgme_set_override_inst_dir (value);
  else
    return -1;
}



/* Create a new context as an environment for GPGME crypto
   operations.  */
gpgme_error_t
gpgme_new (gpgme_ctx_t *r_ctx)
{
  gpgme_error_t err;
  gpgme_ctx_t ctx;
  TRACE_BEG (DEBUG_CTX, "gpgme_new", r_ctx, "");

  if (_gpgme_selftest)
    return TRACE_ERR (_gpgme_selftest);

  if (!r_ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    return TRACE_ERR (gpg_error_from_syserror ());

  INIT_LOCK (ctx->lock);

  err = _gpgme_engine_info_copy (&ctx->engine_info);
  if (!err && !ctx->engine_info)
    err = gpg_error (GPG_ERR_NO_ENGINE);
  if (err)
    {
      free (ctx);
      return TRACE_ERR (err);
    }

  ctx->keylist_mode = GPGME_KEYLIST_MODE_LOCAL;
  ctx->include_certs = GPGME_INCLUDE_CERTS_DEFAULT;
  ctx->protocol = GPGME_PROTOCOL_OpenPGP;
  ctx->sub_protocol = GPGME_PROTOCOL_DEFAULT;
  _gpgme_fd_table_init (&ctx->fdt);

  LOCK (def_lc_lock);
  if (def_lc_ctype)
    {
      ctx->lc_ctype = strdup (def_lc_ctype);
      if (!ctx->lc_ctype)
	{
          int saved_err = gpg_error_from_syserror ();
	  UNLOCK (def_lc_lock);
	  _gpgme_engine_info_release (ctx->engine_info);
	  free (ctx);
	  return TRACE_ERR (saved_err);
	}
    }
  else
    def_lc_ctype = NULL;

  if (def_lc_messages)
    {
      ctx->lc_messages = strdup (def_lc_messages);
      if (!ctx->lc_messages)
	{
          int saved_err = gpg_error_from_syserror ();
	  UNLOCK (def_lc_lock);
	  if (ctx->lc_ctype)
	    free (ctx->lc_ctype);
	  _gpgme_engine_info_release (ctx->engine_info);
	  free (ctx);
	  return TRACE_ERR (saved_err);
	}
    }
  else
    def_lc_messages = NULL;
  UNLOCK (def_lc_lock);

  *r_ctx = ctx;

  TRACE_SUC ("ctx=%p", ctx);
  return 0;
}


gpgme_error_t
_gpgme_cancel_with_err (gpgme_ctx_t ctx, gpg_error_t ctx_err,
			gpg_error_t op_err)
{
  gpgme_error_t err;
  struct gpgme_io_event_done_data data;

  TRACE_BEG  (DEBUG_CTX, "_gpgme_cancel_with_err", ctx, "ctx_err=%i, op_err=%i",
	      ctx_err, op_err);

  if (ctx_err)
    {
      err = _gpgme_engine_cancel (ctx->engine);
      if (err)
	return TRACE_ERR (err);
    }
  else
    {
      err = _gpgme_engine_cancel_op (ctx->engine);
      if (err)
	return TRACE_ERR (err);
    }

  data.err = ctx_err;
  data.op_err = op_err;

  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &data);

  return TRACE_ERR (0);
}


/* Cancel a pending asynchronous operation.  */
gpgme_error_t
gpgme_cancel (gpgme_ctx_t ctx)
{
  gpg_error_t err;

  TRACE_BEG (DEBUG_CTX, "gpgme_cancel", ctx, "");

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  err = _gpgme_cancel_with_err (ctx, gpg_error (GPG_ERR_CANCELED), 0);

  return TRACE_ERR (err);
}


/* Cancel a pending operation asynchronously.  */
gpgme_error_t
gpgme_cancel_async (gpgme_ctx_t ctx)
{
  TRACE_BEG (DEBUG_CTX, "gpgme_cancel_async", ctx, "");

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  LOCK (ctx->lock);
  ctx->canceled = 1;
  UNLOCK (ctx->lock);

  return TRACE_ERR (0);
}


/* Release all resources associated with the given context.  */
void
gpgme_release (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_release", ctx, "");

  if (!ctx)
    return;

  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  _gpgme_fd_table_deinit (&ctx->fdt);
  _gpgme_release_result (ctx);
  _gpgme_signers_clear (ctx);
  _gpgme_sig_notation_clear (ctx);
  free (ctx->sender);
  free (ctx->signers);
  free (ctx->lc_ctype);
  free (ctx->lc_messages);
  free (ctx->override_session_key);
  free (ctx->request_origin);
  free (ctx->auto_key_locate);
  free (ctx->trust_model);
  free (ctx->cert_expire);
  free (ctx->key_origin);
  free (ctx->import_filter);
  free (ctx->import_options);
  _gpgme_engine_info_release (ctx->engine_info);
  ctx->engine_info = NULL;
  DESTROY_LOCK (ctx->lock);
  free (ctx);
}


void
gpgme_result_ref (void *result)
{
  struct ctx_op_data *data;

  if (! result)
    return;

  data = (void*)((char*)result - sizeof (struct ctx_op_data));

  assert (data->magic == CTX_OP_DATA_MAGIC);

  LOCK (result_ref_lock);
  data->references++;
  UNLOCK (result_ref_lock);
}


void
gpgme_result_unref (void *result)
{
  struct ctx_op_data *data;

  if (! result)
    return;

  data = (void*)((char*)result - sizeof (struct ctx_op_data));

  assert (data->magic == CTX_OP_DATA_MAGIC);

  LOCK (result_ref_lock);
  if (--data->references)
    {
      UNLOCK (result_ref_lock);
      return;
    }
  UNLOCK (result_ref_lock);

  if (data->cleanup)
    (*data->cleanup) (data->hook);
  free (data);
}


void
_gpgme_release_result (gpgme_ctx_t ctx)
{
  struct ctx_op_data *data = ctx->op_data;

  while (data)
    {
      struct ctx_op_data *next_data = data->next;
      data->next = NULL;
      gpgme_result_unref (data->hook);
      data = next_data;
    }
  ctx->op_data = NULL;
}


/* Note that setting the protocol will intentionally not fail if the
 * engine is not available.  */
gpgme_error_t
gpgme_set_protocol (gpgme_ctx_t ctx, gpgme_protocol_t protocol)
{
  TRACE_BEG  (DEBUG_CTX, "gpgme_set_protocol", ctx, "protocol=%i (%s)",
	      protocol, gpgme_get_protocol_name (protocol)
	      ? gpgme_get_protocol_name (protocol) : "invalid");

  if (protocol != GPGME_PROTOCOL_OpenPGP
      && protocol != GPGME_PROTOCOL_CMS
      && protocol != GPGME_PROTOCOL_GPGCONF
      && protocol != GPGME_PROTOCOL_ASSUAN
      && protocol != GPGME_PROTOCOL_G13
      && protocol != GPGME_PROTOCOL_UISERVER
      && protocol != GPGME_PROTOCOL_SPAWN)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (ctx->protocol != protocol)
    {
      /* Shut down the engine when switching protocols.  */
      if (ctx->engine)
	{
	  TRACE_LOG  ("releasing ctx->engine=%p", ctx->engine);
	  _gpgme_engine_release (ctx->engine);
	  ctx->engine = NULL;
	}

      ctx->protocol = protocol;
    }
  return TRACE_ERR (0);
}


gpgme_protocol_t
gpgme_get_protocol (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_protocol", ctx,
	  "ctx->protocol=%i (%s)", ctx->protocol,
	  gpgme_get_protocol_name (ctx->protocol)
	  ? gpgme_get_protocol_name (ctx->protocol) : "invalid");

  return ctx->protocol;
}


gpgme_error_t
gpgme_set_sub_protocol (gpgme_ctx_t ctx, gpgme_protocol_t protocol)
{
  TRACE (DEBUG_CTX, "gpgme_set_sub_protocol", ctx, "protocol=%i (%s)",
	  protocol, gpgme_get_protocol_name (protocol)
	  ? gpgme_get_protocol_name (protocol) : "invalid");

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  ctx->sub_protocol = protocol;
  return 0;
}


gpgme_protocol_t
gpgme_get_sub_protocol (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_sub_protocol", ctx,
	  "ctx->sub_protocol=%i (%s)", ctx->sub_protocol,
	  gpgme_get_protocol_name (ctx->sub_protocol)
	  ? gpgme_get_protocol_name (ctx->sub_protocol) : "invalid");

  return ctx->sub_protocol;
}


const char *
gpgme_get_protocol_name (gpgme_protocol_t protocol)
{
  switch (protocol)
    {
    case GPGME_PROTOCOL_OpenPGP:
      return "OpenPGP";

    case GPGME_PROTOCOL_CMS:
      return "CMS";

    case GPGME_PROTOCOL_GPGCONF:
      return "GPGCONF";

    case GPGME_PROTOCOL_ASSUAN:
      return "Assuan";

    case GPGME_PROTOCOL_G13:
      return "G13";

    case GPGME_PROTOCOL_UISERVER:
      return "UIServer";

    case GPGME_PROTOCOL_SPAWN:
      return "Spawn";

    case GPGME_PROTOCOL_DEFAULT:
      return "default";

    case GPGME_PROTOCOL_UNKNOWN:
      return "unknown";

    default:
      return NULL;
    }
}


/* Store the sender's address in the context.  ADDRESS is addr-spec of
 * mailbox but my also be a complete mailbox, in which case this
 * function extracts the addr-spec from it.  Returns 0 on success or
 * an error code if no valid addr-spec could be extracted from
 * ADDRESS.  */
gpgme_error_t
gpgme_set_sender (gpgme_ctx_t ctx, const char *address)
{
  char *p = NULL;

  TRACE_BEG  (DEBUG_CTX, "gpgme_set_sender", ctx, "sender='%s'",
              address?address:"(null)");

  if (!ctx || (address && !(p = _gpgme_mailbox_from_userid (address))))
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  free (ctx->sender);
  ctx->sender = p;
  return TRACE_ERR (0);
}


/* Return the sender's address (addr-spec part) from the context or
 * NULL if none was set.  The returned value is valid as long as the
 * CTX is valid and gpgme_set_sender has not been used.  */
const char *
gpgme_get_sender (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_sender", ctx, "sender='%s'",
          ctx?ctx->sender:"");

  return ctx->sender;
}


/* Enable or disable the use of an ascii armor for all output.  */
void
gpgme_set_armor (gpgme_ctx_t ctx, int use_armor)
{
  TRACE (DEBUG_CTX, "gpgme_set_armor", ctx, "use_armor=%i (%s)",
	  use_armor, use_armor ? "yes" : "no");

  if (!ctx)
    return;

  ctx->use_armor = !!use_armor;
}


/* Return the state of the armor flag.  */
int
gpgme_get_armor (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_armor", ctx, "ctx->use_armor=%i (%s)",
	  ctx->use_armor, ctx->use_armor ? "yes" : "no");
  return ctx->use_armor;
}


/* Set the flag NAME for CTX to VALUE.  Please consult the manual for
 * a description of the flags.
 */
gpgme_error_t
gpgme_set_ctx_flag (gpgme_ctx_t ctx, const char *name, const char *value)
{
  gpgme_error_t err = 0;
  int abool;

  TRACE (DEBUG_CTX, "gpgme_set_ctx_flag", ctx,
          "name='%s' value='%s'",
	  name? name:"(null)", value?value:"(null)");

  abool = (value && *value)? !!atoi (value) : 0;

  if (!ctx || !name || !value)
    err = gpg_error (GPG_ERR_INV_VALUE);
  else if (!strcmp (name, "redraw"))
    {
      ctx->redraw_suggested = abool;
    }
  else if (!strcmp (name, "full-status"))
    {
      ctx->full_status = abool;
    }
  else if (!strcmp (name, "raw-description"))
    {
      ctx->raw_description = abool;
    }
  else if (!strcmp (name, "export-session-key"))
    {
      ctx->export_session_keys = abool;
    }
  else if (!strcmp (name, "override-session-key"))
    {
      free (ctx->override_session_key);
      ctx->override_session_key = strdup (value);
      if (!ctx->override_session_key)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "include-key-block"))
    {
      ctx->include_key_block = abool;
    }
  else if (!strcmp (name, "auto-key-import"))
    {
      ctx->auto_key_import = abool;
    }
  else if (!strcmp (name, "auto-key-retrieve"))
    {
      ctx->auto_key_retrieve = abool;
    }
  else if (!strcmp (name, "request-origin"))
    {
      free (ctx->request_origin);
      ctx->request_origin = strdup (value);
      if (!ctx->request_origin)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "no-symkey-cache"))
    {
      ctx->no_symkey_cache = abool;
    }
  else if (!strcmp (name, "ignore-mdc-error"))
    {
      ctx->ignore_mdc_error = abool;
    }
  else if (!strcmp (name, "auto-key-locate"))
    {
      free (ctx->auto_key_locate);
      ctx->auto_key_locate = strdup (value);
      if (!ctx->auto_key_locate)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "trust-model"))
    {
      free (ctx->trust_model);
      ctx->trust_model = strdup (value);
      if (!ctx->trust_model)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "extended-edit"))
    {
      ctx->extended_edit = abool;
    }
  else if (!strcmp (name, "cert-expire"))
    {
      free (ctx->cert_expire);
      ctx->cert_expire = strdup (value);
      if (!ctx->cert_expire)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "key-origin"))
    {
      free (ctx->key_origin);
      ctx->key_origin = strdup (value);
      if (!ctx->key_origin)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "import-filter"))
    {
      free (ctx->import_filter);
      ctx->import_filter = strdup (value);
      if (!ctx->import_filter)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "import-options"))
    {
      free (ctx->import_options);
      ctx->import_options = strdup (value);
      if (!ctx->import_options)
        err = gpg_error_from_syserror ();
    }
  else if (!strcmp (name, "no-auto-check-trustdb"))
    {
      ctx->no_auto_check_trustdb = abool;
    }
  else
    err = gpg_error (GPG_ERR_UNKNOWN_NAME);

  return err;
}


/* Get the context flag named NAME.  See gpgme_set_ctx_flag for a list
 * of valid names.  If the NAME is unknown NULL is returned.  For a
 * boolean flag an empty string is returned for False and the string
 * "1" for True; thus either atoi or a simple string test can be
 * used.  */
const char *
gpgme_get_ctx_flag (gpgme_ctx_t ctx, const char *name)
{
  if (!ctx || !name)
    return NULL;
  else if (!strcmp (name, "redraw"))
    {
      return ctx->redraw_suggested? "1":"";
    }
  else if (!strcmp (name, "full-status"))
    {
      return ctx->full_status? "1":"";
    }
  else if (!strcmp (name, "raw-description"))
    {
      return ctx->raw_description? "1":"";
    }
  else if (!strcmp (name, "export-session-key"))
    {
      return ctx->export_session_keys? "1":"";
    }
  else if (!strcmp (name, "override-session-key"))
    {
      return ctx->override_session_key? ctx->override_session_key : "";
    }
  else if (!strcmp (name, "include-key-block"))
    {
      return ctx->include_key_block? "1":"";
    }
  else if (!strcmp (name, "auto-key-import"))
    {
      return ctx->auto_key_import? "1":"";
    }
  else if (!strcmp (name, "auto-key-retrieve"))
    {
      return ctx->auto_key_retrieve? "1":"";
    }
  else if (!strcmp (name, "request-origin"))
    {
      return ctx->request_origin? ctx->request_origin : "";
    }
  else if (!strcmp (name, "no-symkey-cache"))
    {
      return ctx->no_symkey_cache? "1":"";
    }
  else if (!strcmp (name, "ignore-mdc-error"))
    {
      return ctx->ignore_mdc_error? "1":"";
    }
  else if (!strcmp (name, "auto-key-locate"))
    {
      return ctx->auto_key_locate? ctx->auto_key_locate : "";
    }
  else if (!strcmp (name, "extended-edit"))
    {
      return ctx->extended_edit ? "1":"";
    }
  else if (!strcmp (name, "cert-expire"))
    {
      return ctx->cert_expire? ctx->cert_expire : "";
    }
  else if (!strcmp (name, "key-origin"))
    {
      return ctx->key_origin? ctx->key_origin : "";
    }
  else if (!strcmp (name, "import-filter"))
    {
      return ctx->import_filter? ctx->import_filter : "";
    }
  else if (!strcmp (name, "import-options"))
    {
      return ctx->import_options? ctx->import_options : "";
    }
  else if (!strcmp (name, "no-auto-check-trustdb"))
    {
      return ctx->no_auto_check_trustdb? "1":"";
    }
  else
    return NULL;
}


/* Enable or disable the use of the special textmode.  Textmode is for
  example used for the RFC2015 signatures; note that the updated RFC
  3156 mandates that the MUA does some preparations so that textmode
  is not needed anymore.  */
void
gpgme_set_textmode (gpgme_ctx_t ctx, int use_textmode)
{
  TRACE (DEBUG_CTX, "gpgme_set_textmode", ctx, "use_textmode=%i (%s)",
	  use_textmode, use_textmode ? "yes" : "no");

  if (!ctx)
    return;

  ctx->use_textmode = !!use_textmode;
}

/* Return the state of the textmode flag.  */
int
gpgme_get_textmode (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_textmode", ctx, "ctx->use_textmode=%i (%s)",
	  ctx->use_textmode, ctx->use_textmode ? "yes" : "no");
  return ctx->use_textmode;
}


/* Enable offline mode for this context. In offline mode dirmngr
  will be disabled. */
void
gpgme_set_offline (gpgme_ctx_t ctx, int offline)
{
  TRACE (DEBUG_CTX, "gpgme_set_offline", ctx, "offline=%i (%s)",
          offline, offline ? "yes" : "no");

  if (!ctx)
    return;

  ctx->offline = !!offline;
}

/* Return the state of the offline flag.  */
int
gpgme_get_offline (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_offline", ctx, "ctx->offline=%i (%s)",
          ctx->offline, ctx->offline ? "yes" : "no");
  return ctx->offline;
}


/* Set the number of certifications to include in an S/MIME message.
   The default is GPGME_INCLUDE_CERTS_DEFAULT.  -1 means all certs,
   and -2 means all certs except the root cert.  */
void
gpgme_set_include_certs (gpgme_ctx_t ctx, int nr_of_certs)
{
  if (!ctx)
    return;

  if (nr_of_certs == GPGME_INCLUDE_CERTS_DEFAULT)
    ctx->include_certs = GPGME_INCLUDE_CERTS_DEFAULT;
  else if (nr_of_certs < -2)
    ctx->include_certs = -2;
  else
    ctx->include_certs = nr_of_certs;

  TRACE (DEBUG_CTX, "gpgme_set_include_certs", ctx, "nr_of_certs=%i%s",
	  nr_of_certs, nr_of_certs == ctx->include_certs ? "" : " (-2)");
}


/* Get the number of certifications to include in an S/MIME
   message.  */
int
gpgme_get_include_certs (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_include_certs", ctx, "ctx->include_certs=%i",
	  ctx->include_certs);
  return ctx->include_certs;
}


/* This function changes the default behaviour of the keylisting
   functions.  MODE is a bitwise-OR of the GPGME_KEYLIST_* flags.  The
   default mode is GPGME_KEYLIST_MODE_LOCAL.  */
gpgme_error_t
gpgme_set_keylist_mode (gpgme_ctx_t ctx, gpgme_keylist_mode_t mode)
{
  TRACE (DEBUG_CTX, "gpgme_set_keylist_mode", ctx, "keylist_mode=0x%x",
	  mode);

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  if ((mode & GPGME_KEYLIST_MODE_LOCATE_EXTERNAL) ==
      (GPGME_KEYLIST_MODE_LOCAL|GPGME_KEYLIST_MODE_FORCE_EXTERN))
    return gpg_error (GPG_ERR_INV_VALUE);

  ctx->keylist_mode = mode;
  return 0;
}

/* This function returns the default behaviour of the keylisting
   functions.  */
gpgme_keylist_mode_t
gpgme_get_keylist_mode (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_keylist_mode", ctx,
	  "ctx->keylist_mode=0x%x", ctx->keylist_mode);
  return ctx->keylist_mode;
}


/* Set the pinentry mode for CTX to MODE. */
gpgme_error_t
gpgme_set_pinentry_mode (gpgme_ctx_t ctx, gpgme_pinentry_mode_t mode)
{
  TRACE (DEBUG_CTX, "gpgme_set_pinentry_mode", ctx, "pinentry_mode=%u",
	  (unsigned int)mode);

  if (!ctx)
    return gpg_error (GPG_ERR_INV_VALUE);

  switch (mode)
    {
    case GPGME_PINENTRY_MODE_DEFAULT:
    case GPGME_PINENTRY_MODE_ASK:
    case GPGME_PINENTRY_MODE_CANCEL:
    case GPGME_PINENTRY_MODE_ERROR:
    case GPGME_PINENTRY_MODE_LOOPBACK:
      break;
    default:
      return gpg_error (GPG_ERR_INV_VALUE);
    }

  ctx->pinentry_mode = mode;
  return 0;
}


/* Get the pinentry mode of CTX.  */
gpgme_pinentry_mode_t
gpgme_get_pinentry_mode (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_get_pinentry_mode", ctx,
	  "ctx->pinentry_mode=%u", (unsigned int)ctx->pinentry_mode);
  return ctx->pinentry_mode;
}


/* This function sets a callback function to be used to pass a
   passphrase to gpg.  */
void
gpgme_set_passphrase_cb (gpgme_ctx_t ctx, gpgme_passphrase_cb_t cb,
			 void *cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_set_passphrase_cb", ctx,
	  "passphrase_cb=%p/%p", cb, cb_value);

  if (!ctx)
    return;

  ctx->passphrase_cb = cb;
  ctx->passphrase_cb_value = cb_value;
}


/* This function returns the callback function to be used to pass a
   passphrase to the crypto engine.  */
void
gpgme_get_passphrase_cb (gpgme_ctx_t ctx, gpgme_passphrase_cb_t *r_cb,
			 void **r_cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_get_passphrase_cb", ctx,
	  "ctx->passphrase_cb=%p/%p",
	  ctx->passphrase_cb, ctx->passphrase_cb_value);
  if (r_cb)
    *r_cb = ctx->passphrase_cb;
  if (r_cb_value)
    *r_cb_value = ctx->passphrase_cb_value;
}


/* This function sets a callback function to be used as a progress
   indicator.  */
void
gpgme_set_progress_cb (gpgme_ctx_t ctx, gpgme_progress_cb_t cb, void *cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_set_progress_cb", ctx, "progress_cb=%p/%p",
	  cb, cb_value);

  if (!ctx)
    return;

  ctx->progress_cb = cb;
  ctx->progress_cb_value = cb_value;
}


/* This function returns the callback function to be used as a
   progress indicator.  */
void
gpgme_get_progress_cb (gpgme_ctx_t ctx, gpgme_progress_cb_t *r_cb,
		       void **r_cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_get_progress_cb", ctx, "ctx->progress_cb=%p/%p",
	  ctx->progress_cb, ctx->progress_cb_value);
  if (r_cb)
    *r_cb = ctx->progress_cb;
  if (r_cb_value)
    *r_cb_value = ctx->progress_cb_value;
}


/* This function sets a callback function to be used as a status
   message forwarder.  */
void
gpgme_set_status_cb (gpgme_ctx_t ctx, gpgme_status_cb_t cb, void *cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_set_status_cb", ctx, "status_cb=%p/%p",
	  cb, cb_value);

  if (!ctx)
    return;

  ctx->status_cb = cb;
  ctx->status_cb_value = cb_value;
}


/* This function returns the callback function to be used as a
   status message forwarder.  */
void
gpgme_get_status_cb (gpgme_ctx_t ctx, gpgme_status_cb_t *r_cb,
		       void **r_cb_value)
{
  TRACE (DEBUG_CTX, "gpgme_get_status_cb", ctx, "ctx->status_cb=%p/%p",
	  ctx ? ctx->status_cb : NULL, ctx ? ctx->status_cb_value : NULL);

  if (r_cb)
    *r_cb = NULL;

  if (r_cb_value)
    *r_cb_value = NULL;

  if (!ctx || !ctx->status_cb)
    return;

  if (r_cb)
    *r_cb = ctx->status_cb;
  if (r_cb_value)
    *r_cb_value = ctx->status_cb_value;
}


/* Set the I/O callback functions for CTX to IO_CBS.  */
void
gpgme_set_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs)
{
  if (!ctx)
    return;

  if (io_cbs)
    {
      TRACE (DEBUG_CTX, "gpgme_set_io_cbs", ctx,
	      "io_cbs=%p (add=%p/%p, remove=%p, event=%p/%p",
	      io_cbs, io_cbs->add, io_cbs->add_priv, io_cbs->remove,
	      io_cbs->event, io_cbs->event_priv);
      ctx->io_cbs = *io_cbs;
    }
  else
    {
      TRACE (DEBUG_CTX, "gpgme_set_io_cbs", ctx,
	      "io_cbs=%p (default)", io_cbs);
      ctx->io_cbs.add = NULL;
      ctx->io_cbs.add_priv = NULL;
      ctx->io_cbs.remove = NULL;
      ctx->io_cbs.event = NULL;
      ctx->io_cbs.event_priv = NULL;
    }
}


/* This function provides access to the internal read function; it is
   normally not used.  */
gpgme_ssize_t
gpgme_io_read (int fd, void *buffer, size_t count)
{
  int ret;
  TRACE_BEG  (DEBUG_GLOBAL, "gpgme_io_read", fd,
	      "buffer=%p, count=%zu", buffer, count);

  ret = _gpgme_io_read (fd, buffer, count);

  return TRACE_SYSRES (ret);
}


/* This function provides access to the internal write function.  It
   is to be used by user callbacks to return data to gpgme.  See
   gpgme_passphrase_cb_t and gpgme_edit_cb_t.  */
gpgme_ssize_t
gpgme_io_write (int fd, const void *buffer, size_t count)
{
  int ret;
  TRACE_BEG  (DEBUG_GLOBAL, "gpgme_io_write", fd,
	      "buffer=%p, count=%zu", buffer, count);

  ret = _gpgme_io_write (fd, buffer, count);

  return TRACE_SYSRES (ret);
}

/* This function provides access to the internal write function.  It
   is to be used by user callbacks to return data to gpgme.  See
   gpgme_passphrase_cb_t and gpgme_edit_cb_t.  Note that this is a
   variant of gpgme_io_write which guarantees that all COUNT bytes are
   written or an error is return.  Returns: 0 on success or -1 on
   error and the sets errno. */
int
gpgme_io_writen (int fd, const void *buffer_arg, size_t count)
{
  const char *buffer = buffer_arg;
  int ret = 0;
  TRACE_BEG  (DEBUG_GLOBAL, "gpgme_io_writen", fd,
	      "buffer=%p, count=%zu", buffer, count);
  while (count)
    {
      ret = _gpgme_io_write (fd, buffer, count);
      if (ret < 0)
        break;
      buffer += ret;
      count -= ret;
      ret = 0;
    }
  return TRACE_SYSRES (ret);
}


/* This function returns the callback function for I/O.  */
void
gpgme_get_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs)
{
  TRACE (DEBUG_CTX, "gpgme_get_io_cbs", ctx,
	  "io_cbs=%p, ctx->io_cbs.add=%p/%p, .remove=%p, .event=%p/%p",
	  io_cbs, io_cbs->add, io_cbs->add_priv, io_cbs->remove,
	  io_cbs->event, io_cbs->event_priv);

  *io_cbs = ctx->io_cbs;
}


/* This function sets the locale for the context CTX, or the default
   locale if CTX is a null pointer.  */
gpgme_error_t
gpgme_set_locale (gpgme_ctx_t ctx, int category, const char *value)
{
  int failed = 0;
  char *new_lc_ctype = NULL;
  char *new_lc_messages = NULL;

  TRACE_BEG  (DEBUG_CTX, "gpgme_set_locale", ctx,
	       "category=%i, value=%s", category, value ? value : "(null)");

#define PREPARE_ONE_LOCALE(lcat, ucat)				\
  if (!failed && value						\
      && (category == LC_ALL || category == LC_ ## ucat))	\
    {								\
      new_lc_ ## lcat = strdup (value);				\
      if (!new_lc_ ## lcat)					\
        failed = 1;						\
    }

#ifdef LC_CTYPE
  PREPARE_ONE_LOCALE (ctype, CTYPE);
#endif
#ifdef LC_MESSAGES
  PREPARE_ONE_LOCALE (messages, MESSAGES);
#endif

  if (failed)
    {
      int saved_err = gpg_error_from_syserror ();

      if (new_lc_ctype)
	free (new_lc_ctype);
      if (new_lc_messages)
	free (new_lc_messages);

      return TRACE_ERR (saved_err);
    }

#define SET_ONE_LOCALE(lcat, ucat)			\
  if (category == LC_ALL || category == LC_ ## ucat)	\
    {							\
      if (ctx)						\
	{						\
	  if (ctx->lc_ ## lcat)				\
	    free (ctx->lc_ ## lcat);			\
	  ctx->lc_ ## lcat = new_lc_ ## lcat;		\
	}						\
      else						\
	{						\
	  if (def_lc_ ## lcat)				\
	    free (def_lc_ ## lcat);			\
	  def_lc_ ## lcat = new_lc_ ## lcat;		\
	}						\
    }

  if (!ctx)
    LOCK (def_lc_lock);
#ifdef LC_CTYPE
  SET_ONE_LOCALE (ctype, CTYPE);
#endif
#ifdef LC_MESSAGES
  SET_ONE_LOCALE (messages, MESSAGES);
#endif
  if (!ctx)
    UNLOCK (def_lc_lock);

  return TRACE_ERR (0);
}


/* Get the information about the configured engines.  A pointer to the
   first engine in the statically allocated linked list is returned.
   The returned data is valid until the next gpgme_ctx_set_engine_info.  */
gpgme_engine_info_t
gpgme_ctx_get_engine_info (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_ctx_get_engine_info", ctx,
	  "ctx->engine_info=%p", ctx->engine_info);
  return ctx->engine_info;
}


/* Set the engine info for the context CTX, protocol PROTO, to the
   file name FILE_NAME and the home directory HOME_DIR.  */
gpgme_error_t
gpgme_ctx_set_engine_info (gpgme_ctx_t ctx, gpgme_protocol_t proto,
			   const char *file_name, const char *home_dir)
{
  gpgme_error_t err;
  TRACE_BEG  (DEBUG_CTX, "gpgme_ctx_set_engine_info", ctx,
	      "protocol=%i (%s), file_name=%s, home_dir=%s",
	      proto, gpgme_get_protocol_name (proto)
	      ? gpgme_get_protocol_name (proto) : "unknown",
	      file_name ? file_name : "(default)",
	      home_dir ? home_dir : "(default)");

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  /* Shut down the engine when changing engine info.  */
  if (ctx->engine)
    {
      TRACE_LOG  ("releasing ctx->engine=%p", ctx->engine);
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  err = _gpgme_set_engine_info (ctx->engine_info, proto,
				file_name, home_dir);
  return TRACE_ERR (err);
}


/* Clear all notation data from the context.  */
void
_gpgme_sig_notation_clear (gpgme_ctx_t ctx)
{
  gpgme_sig_notation_t notation;

  if (!ctx)
    return;

  notation = ctx->sig_notations;
  while (notation)
    {
      gpgme_sig_notation_t next_notation = notation->next;
      _gpgme_sig_notation_free (notation);
      notation = next_notation;
    }
  ctx->sig_notations = NULL;
}

void
gpgme_sig_notation_clear (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_sig_notation_clear", ctx, "");

  if (!ctx)
    return;

  _gpgme_sig_notation_clear (ctx);
}


/* Add the human-readable notation data with name NAME and value VALUE
   to the context CTX, using the flags FLAGS.  If NAME is NULL, then
   VALUE should be a policy URL.  The flag
   GPGME_SIG_NOTATION_HUMAN_READABLE is forced to be true for notation
   data, and false for policy URLs.  */
gpgme_error_t
gpgme_sig_notation_add (gpgme_ctx_t ctx, const char *name,
			const char *value, gpgme_sig_notation_flags_t flags)
{
  gpgme_error_t err;
  gpgme_sig_notation_t notation;
  gpgme_sig_notation_t *lastp;

  TRACE_BEG  (DEBUG_CTX, "gpgme_sig_notation_add", ctx,
	      "name=%s, value=%s, flags=0x%x",
	      name ? name : "(null)", value ? value : "(null)",
	      flags);

  if (!ctx)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (name)
    flags |= GPGME_SIG_NOTATION_HUMAN_READABLE;
  else
    flags &= ~GPGME_SIG_NOTATION_HUMAN_READABLE;

  err = _gpgme_sig_notation_create (&notation, name, name ? strlen (name) : 0,
				    value, value ? strlen (value) : 0, flags);
  if (err)
    return TRACE_ERR (err);

  lastp = &ctx->sig_notations;
  while (*lastp)
    lastp = &(*lastp)->next;

  *lastp = notation;
  return TRACE_ERR (0);
}


/* Get the sig notations for this context.  */
gpgme_sig_notation_t
gpgme_sig_notation_get (gpgme_ctx_t ctx)
{
  if (!ctx)
    {
      TRACE (DEBUG_CTX, "gpgme_sig_notation_get", ctx, "");
      return NULL;
    }
  TRACE (DEBUG_CTX, "gpgme_sig_notation_get", ctx,
	  "ctx->sig_notations=%p", ctx->sig_notations);

  return ctx->sig_notations;
}



/* Return a public key algorithm string made of the algorithm and size
   or the curve name.  May return NULL on error.  Caller must free the
   result using gpgme_free.  */
char *
gpgme_pubkey_algo_string (gpgme_subkey_t subkey)
{
  const char *prefix = NULL;
  char *result;

  if (!subkey)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  switch (subkey->pubkey_algo)
    {
    case GPGME_PK_RSA:
    case GPGME_PK_RSA_E:
    case GPGME_PK_RSA_S: prefix = "rsa"; break;
    case GPGME_PK_ELG_E: prefix = "elg"; break;
    case GPGME_PK_DSA:	 prefix = "dsa"; break;
    case GPGME_PK_ELG:   prefix = "xxx"; break;
    case GPGME_PK_ECC:
    case GPGME_PK_ECDH:
    case GPGME_PK_ECDSA:
    case GPGME_PK_EDDSA: prefix = "";    break;
    }

  if (prefix && *prefix)
    {
      char buffer[40];
      snprintf (buffer, sizeof buffer, "%s%u", prefix, subkey->length);
      result = strdup (buffer);
    }
  else if (prefix && subkey->curve && *subkey->curve)
    result = strdup (subkey->curve);
  else if (prefix)
    result =  strdup ("E_error");
  else
    result = strdup  ("unknown");

  return result;
}


const char *
gpgme_pubkey_algo_name (gpgme_pubkey_algo_t algo)
{
  switch (algo)
    {
    case GPGME_PK_RSA:   return "RSA";
    case GPGME_PK_RSA_E: return "RSA-E";
    case GPGME_PK_RSA_S: return "RSA-S";
    case GPGME_PK_ELG_E: return "ELG-E";
    case GPGME_PK_DSA:   return "DSA";
    case GPGME_PK_ECC:   return "ECC";
    case GPGME_PK_ELG:   return "ELG";
    case GPGME_PK_ECDSA: return "ECDSA";
    case GPGME_PK_ECDH:  return "ECDH";
    case GPGME_PK_EDDSA: return "EdDSA";
    default:             return NULL;
    }
}


const char *
gpgme_hash_algo_name (gpgme_hash_algo_t algo)
{
  switch (algo)
    {
    case GPGME_MD_MD5:
      return "MD5";

    case GPGME_MD_SHA1:
      return "SHA1";

    case GPGME_MD_RMD160:
      return "RIPEMD160";

    case GPGME_MD_MD2:
      return "MD2";

    case GPGME_MD_TIGER:
      return "TIGER192";

    case GPGME_MD_HAVAL:
      return "HAVAL";

    case GPGME_MD_SHA256:
      return "SHA256";

    case GPGME_MD_SHA384:
      return "SHA384";

    case GPGME_MD_SHA512:
      return "SHA512";

    case GPGME_MD_SHA224:
      return "SHA224";

    case GPGME_MD_MD4:
      return "MD4";

    case GPGME_MD_CRC32:
      return "CRC32";

    case GPGME_MD_CRC32_RFC1510:
      return "CRC32RFC1510";

    case GPGME_MD_CRC24_RFC2440:
      return "CRC24RFC2440";

    default:
      return NULL;
    }
}

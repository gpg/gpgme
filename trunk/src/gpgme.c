/* gpgme.c - GnuPG Made Easy.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007 g10 Code GmbH

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
#include <locale.h>

#include "util.h"
#include "context.h"
#include "ops.h"
#include "wait.h"
#include "debug.h"


/* The default locale.  */
DEFINE_STATIC_LOCK (def_lc_lock);
static char *def_lc_ctype;
static char *def_lc_messages;


/* Create a new context as an environment for GPGME crypto
   operations.  */
gpgme_error_t
gpgme_new (gpgme_ctx_t *r_ctx)
{
  gpgme_ctx_t ctx;
  TRACE_BEG (DEBUG_CTX, "gpgme_new", r_ctx);

  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    return TRACE_ERR (gpg_error_from_errno (errno));

  INIT_LOCK (ctx->lock);
  
  _gpgme_engine_info_copy (&ctx->engine_info);
  if (!ctx->engine_info)
    {
      free (ctx);
      return TRACE_ERR (gpg_error_from_errno (errno));
    }

  ctx->keylist_mode = GPGME_KEYLIST_MODE_LOCAL;
  ctx->include_certs = GPGME_INCLUDE_CERTS_DEFAULT;
  ctx->protocol = GPGME_PROTOCOL_OpenPGP;
  _gpgme_fd_table_init (&ctx->fdt);

  LOCK (def_lc_lock);
  if (def_lc_ctype)
    {
      ctx->lc_ctype = strdup (def_lc_ctype);
      if (!ctx->lc_ctype)
	{
	  UNLOCK (def_lc_lock);
	  _gpgme_engine_info_release (ctx->engine_info);
	  free (ctx);
	  return TRACE_ERR (gpg_error_from_errno (errno));
	}
    }
  else
    def_lc_ctype = NULL;

  if (def_lc_messages)
    {
      ctx->lc_messages = strdup (def_lc_messages);
      if (!ctx->lc_messages)
	{
	  UNLOCK (def_lc_lock);
	  if (ctx->lc_ctype)
	    free (ctx->lc_ctype);
	  _gpgme_engine_info_release (ctx->engine_info);
	  free (ctx);
	  return TRACE_ERR (gpg_error_from_errno (errno));
	}
    }
  else
    def_lc_messages = NULL;
  UNLOCK (def_lc_lock);

  *r_ctx = ctx;

  return TRACE_SUC1 ("ctx=%p", ctx);
}


gpgme_error_t
_gpgme_cancel_with_err (gpgme_ctx_t ctx, gpg_error_t ctx_err)
{
  gpgme_error_t err;
  TRACE_BEG1 (DEBUG_CTX, "_gpgme_cancel_with_err", ctx, "ctx_err=%i",
	      ctx_err);

  err = _gpgme_engine_cancel (ctx->engine);
  if (err)
    return TRACE_ERR (err);

  _gpgme_engine_io_event (ctx->engine, GPGME_EVENT_DONE, &ctx_err);

  return TRACE_ERR (0);
}


/* Cancel a pending asynchronous operation.  */
gpgme_error_t
gpgme_cancel (gpgme_ctx_t ctx)
{
  return _gpgme_cancel_with_err (ctx, gpg_error (GPG_ERR_CANCELED));
}


/* Cancel a pending operation asynchronously.  */
gpgme_error_t
gpgme_cancel_async (gpgme_ctx_t ctx)
{
  TRACE_BEG (DEBUG_CTX, "gpgme_cancel_async", ctx);

  LOCK (ctx->lock);
  ctx->canceled = 1;
  UNLOCK (ctx->lock);

  return TRACE_ERR (0);
}


/* Release all resources associated with the given context.  */
void
gpgme_release (gpgme_ctx_t ctx)
{
  TRACE (DEBUG_CTX, "gpgme_release", ctx);

  _gpgme_engine_release (ctx->engine);
  _gpgme_fd_table_deinit (&ctx->fdt);
  _gpgme_release_result (ctx);
  gpgme_signers_clear (ctx);
  gpgme_sig_notation_clear (ctx);
  if (ctx->signers)
    free (ctx->signers);
  if (ctx->lc_ctype)
    free (ctx->lc_ctype);
  if (ctx->lc_messages)
    free (ctx->lc_messages);
  _gpgme_engine_info_release (ctx->engine_info);
  DESTROY_LOCK (ctx->lock);
  free (ctx);
}


void
_gpgme_release_result (gpgme_ctx_t ctx)
{
  struct ctx_op_data *data = ctx->op_data;

  while (data)
    {
      struct ctx_op_data *next_data = data->next;
      if (data->cleanup)
	(*data->cleanup) (data->hook);
      free (data);
      data = next_data;
    }
  ctx->op_data = NULL;
}


gpgme_error_t
gpgme_set_protocol (gpgme_ctx_t ctx, gpgme_protocol_t protocol)
{
  TRACE_BEG2 (DEBUG_CTX, "gpgme_set_protocol", ctx, "protocol=%i (%s)",
	      protocol, gpgme_get_protocol_name (protocol)
	      ? gpgme_get_protocol_name (protocol) : "unknown");

  if (protocol != GPGME_PROTOCOL_OpenPGP && protocol != GPGME_PROTOCOL_CMS)
    return TRACE_ERR (gpg_error (GPG_ERR_INV_VALUE));

  if (ctx->protocol != protocol)
    {
      /* Shut down the engine when switching protocols.  */
      if (ctx->engine)
	{
	  TRACE_LOG1 ("releasing ctx->engine=%p", ctx->engine);
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
  TRACE2 (DEBUG_CTX, "gpgme_get_protocol", ctx,
	  "ctx->protocol=%i (%s)", ctx->protocol,
	  gpgme_get_protocol_name (ctx->protocol)
	  ? gpgme_get_protocol_name (ctx->protocol) : "unknown");
  return ctx->protocol;
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

    case GPGME_PROTOCOL_UNKNOWN:
      return "unknown";

    default:
      return NULL;
    }
}

/* Enable or disable the use of an ascii armor for all output.  */
void
gpgme_set_armor (gpgme_ctx_t ctx, int use_armor)
{
  TRACE2 (DEBUG_CTX, "gpgme_set_armor", ctx, "use_armor=%i (%s)",
	  use_armor, use_armor ? "yes" : "no");
  ctx->use_armor = use_armor;
}


/* Return the state of the armor flag.  */
int
gpgme_get_armor (gpgme_ctx_t ctx)
{
  TRACE2 (DEBUG_CTX, "gpgme_get_armor", ctx, "ctx->use_armor=%i (%s)",
	  ctx->use_armor, ctx->use_armor ? "yes" : "no");
  return ctx->use_armor;
}


/* Enable or disable the use of the special textmode.  Textmode is for
  example used for the RFC2015 signatures; note that the updated RFC
  3156 mandates that the MUA does some preparations so that textmode
  is not needed anymore.  */
void
gpgme_set_textmode (gpgme_ctx_t ctx, int use_textmode)
{
  TRACE2 (DEBUG_CTX, "gpgme_set_textmode", ctx, "use_textmode=%i (%s)",
	  use_textmode, use_textmode ? "yes" : "no");
  ctx->use_textmode = use_textmode;
}

/* Return the state of the textmode flag.  */
int
gpgme_get_textmode (gpgme_ctx_t ctx)
{
  TRACE2 (DEBUG_CTX, "gpgme_get_textmode", ctx, "ctx->use_textmode=%i (%s)",
	  ctx->use_textmode, ctx->use_textmode ? "yes" : "no");
  return ctx->use_textmode;
}


/* Set the number of certifications to include in an S/MIME message.
   The default is GPGME_INCLUDE_CERTS_DEFAULT.  -1 means all certs,
   and -2 means all certs except the root cert.  */
void
gpgme_set_include_certs (gpgme_ctx_t ctx, int nr_of_certs)
{
  if (nr_of_certs == GPGME_INCLUDE_CERTS_DEFAULT)
    ctx->include_certs = GPGME_INCLUDE_CERTS_DEFAULT;
  else if (nr_of_certs < -2)
    ctx->include_certs = -2;
  else
    ctx->include_certs = nr_of_certs;

  TRACE2 (DEBUG_CTX, "gpgme_set_include_certs", ctx, "nr_of_certs=%i%s",
	  nr_of_certs, nr_of_certs == ctx->include_certs ? "" : " (-2)");
}


/* Get the number of certifications to include in an S/MIME
   message.  */
int
gpgme_get_include_certs (gpgme_ctx_t ctx)
{
  TRACE1 (DEBUG_CTX, "gpgme_get_include_certs", ctx, "ctx->include_certs=%i",
	  ctx->include_certs);
  return ctx->include_certs;
}


/* This function changes the default behaviour of the keylisting
   functions.  MODE is a bitwise-OR of the GPGME_KEYLIST_* flags.  The
   default mode is GPGME_KEYLIST_MODE_LOCAL.  */
gpgme_error_t
gpgme_set_keylist_mode (gpgme_ctx_t ctx, gpgme_keylist_mode_t mode)
{
  TRACE1 (DEBUG_CTX, "gpgme_set_keylist_mode", ctx, "keylist_mode=0x%x",
	  mode);

  ctx->keylist_mode = mode;
  return 0;
}

/* This function returns the default behaviour of the keylisting
   functions.  */
gpgme_keylist_mode_t
gpgme_get_keylist_mode (gpgme_ctx_t ctx)
{
  TRACE1 (DEBUG_CTX, "gpgme_get_keylist_mode", ctx,
	  "ctx->keylist_mode=0x%x", ctx->keylist_mode);
  return ctx->keylist_mode;
}


/* This function sets a callback function to be used to pass a
   passphrase to gpg.  */
void
gpgme_set_passphrase_cb (gpgme_ctx_t ctx, gpgme_passphrase_cb_t cb,
			 void *cb_value)
{
  TRACE2 (DEBUG_CTX, "gpgme_set_passphrase_cb", ctx,
	  "passphrase_cb=%p/%p", cb, cb_value);
  ctx->passphrase_cb = cb;
  ctx->passphrase_cb_value = cb_value;
}


/* This function returns the callback function to be used to pass a
   passphrase to the crypto engine.  */
void
gpgme_get_passphrase_cb (gpgme_ctx_t ctx, gpgme_passphrase_cb_t *r_cb,
			 void **r_cb_value)
{
  TRACE2 (DEBUG_CTX, "gpgme_get_passphrase_cb", ctx,
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
  TRACE2 (DEBUG_CTX, "gpgme_set_progress_cb", ctx, "progress_cb=%p/%p",
	  cb, cb_value);
  ctx->progress_cb = cb;
  ctx->progress_cb_value = cb_value;
}


/* This function returns the callback function to be used as a
   progress indicator.  */
void
gpgme_get_progress_cb (gpgme_ctx_t ctx, gpgme_progress_cb_t *r_cb,
		       void **r_cb_value)
{
  TRACE2 (DEBUG_CTX, "gpgme_get_progress_cb", ctx, "ctx->progress_cb=%p/%p",
	  ctx->progress_cb, ctx->progress_cb_value);
  if (r_cb)
    *r_cb = ctx->progress_cb;
  if (r_cb_value)
    *r_cb_value = ctx->progress_cb_value;
}


/* Set the I/O callback functions for CTX to IO_CBS.  */
void
gpgme_set_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs)
{
  if (io_cbs)
    {
      TRACE6 (DEBUG_CTX, "gpgme_set_io_cbs", ctx,
	      "io_cbs=%p (add=%p/%p, remove=%p, event=%p/%p",
	      io_cbs, io_cbs->add, io_cbs->add_priv, io_cbs->remove,
	      io_cbs->event, io_cbs->event_priv);
      ctx->io_cbs = *io_cbs;
    }
  else
    {
      TRACE1 (DEBUG_CTX, "gpgme_set_io_cbs", ctx,
	      "io_cbs=%p (default)", io_cbs);
      ctx->io_cbs.add = NULL;
      ctx->io_cbs.add_priv = NULL;
      ctx->io_cbs.remove = NULL;
      ctx->io_cbs.event = NULL;
      ctx->io_cbs.event_priv = NULL;
    }
}


/* This function returns the callback function for I/O.  */
void
gpgme_get_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs)
{
  TRACE6 (DEBUG_CTX, "gpgme_get_io_cbs", ctx,
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

  TRACE_BEG2 (DEBUG_CTX, "gpgme_set_locale", ctx,
	       "category=%i, value=%s", category, value ? value : "(null)");

#define PREPARE_ONE_LOCALE(lcat, ucat)				\
  if (!failed && value						\
      && (category == LC_ALL || category == LC_ ## ucat))	\
    {								\
      new_lc_ ## lcat = strdup (value);				\
      if (!new_lc_ ## lcat)					\
        failed = 1;						\
    }

  PREPARE_ONE_LOCALE (ctype, CTYPE);
#ifdef LC_MESSAGES
  PREPARE_ONE_LOCALE (messages, MESSAGES);
#endif

  if (failed)
    {
      int saved_errno = errno;

      if (new_lc_ctype)
	free (new_lc_ctype);
      if (new_lc_messages)
	free (new_lc_messages);

      return TRACE_ERR (gpg_error_from_errno (saved_errno));
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
  SET_ONE_LOCALE (ctype, CTYPE);
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
  TRACE1 (DEBUG_CTX, "gpgme_ctx_get_engine_info", ctx,
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
  TRACE_BEG4 (DEBUG_CTX, "gpgme_ctx_set_engine_info", ctx,
	      "protocol=%i (%s), file_name=%s, home_dir=%s",
	      proto, gpgme_get_protocol_name (proto)
	      ? gpgme_get_protocol_name (proto) : "unknown",
	      file_name ? file_name : "(default)",
	      home_dir ? home_dir : "(default)");
	      
  /* Shut down the engine when changing engine info.  */
  if (ctx->engine)
    {
      TRACE_LOG1 ("releasing ctx->engine=%p", ctx->engine);
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  err = _gpgme_set_engine_info (ctx->engine_info, proto,
				file_name, home_dir);
  return TRACE_ERR (err);
}


/* Clear all notation data from the context.  */
void
gpgme_sig_notation_clear (gpgme_ctx_t ctx)
{
  gpgme_sig_notation_t notation;
  TRACE (DEBUG_CTX, "gpgme_sig_notation_clear", ctx);

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

  TRACE_BEG3 (DEBUG_CTX, "gpgme_sig_notation_add", ctx,
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
      TRACE (DEBUG_CTX, "gpgme_sig_notation_get", ctx);
      return NULL;
    }
  TRACE1 (DEBUG_CTX, "gpgme_sig_notation_get", ctx,
	  "ctx->sig_notations=%p", ctx->sig_notations);

  return ctx->sig_notations;
}
  

const char *
gpgme_pubkey_algo_name (gpgme_pubkey_algo_t algo)
{
  switch (algo)
    {
    case GPGME_PK_RSA:
      return "RSA";

    case GPGME_PK_RSA_E:
      return "RSA-E";

    case GPGME_PK_RSA_S:
      return "RSA-S";

    case GPGME_PK_ELG_E:
      return "ELG-E";

    case GPGME_PK_DSA:
      return "DSA";

    case GPGME_PK_ELG:
      return "ELG";

    default:
      return NULL;
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

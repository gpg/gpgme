/* gpgme.c - GnuPG Made Easy.
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
#include "wait.h"

/* Create a new context as an environment for GPGME crypto
   operations.  */
GpgmeError
gpgme_new (GpgmeCtx *r_ctx)
{
  GpgmeCtx ctx;

  if (!r_ctx)
    return GPGME_Invalid_Value;
  *r_ctx = 0;
  ctx = calloc (1, sizeof *ctx);
  if (!ctx)
    return GPGME_Out_Of_Core;
  ctx->keylist_mode = GPGME_KEYLIST_MODE_LOCAL;
  ctx->include_certs = 1;
  ctx->protocol = GPGME_PROTOCOL_OpenPGP;
  _gpgme_fd_table_init (&ctx->fdt);
  *r_ctx = ctx;
  return 0;
}


/**
 * gpgme_release:
 * @c: Context to be released.
 *
 * Release all resources associated with the given context.
 **/
void
gpgme_release (GpgmeCtx ctx)
{
  if (!ctx)
    return;
  _gpgme_engine_release (ctx->engine);
  _gpgme_fd_table_deinit (&ctx->fdt);
  _gpgme_release_result (ctx);
  gpgme_key_release (ctx->tmp_key);
  gpgme_signers_clear (ctx);
  if (ctx->signers)
    free (ctx->signers);
  /* FIXME: Release the key_queue.  */
  free (ctx);
}

void
_gpgme_release_result (GpgmeCtx ctx)
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
  _gpgme_set_op_info (ctx, NULL);
}


/**
 * gpgme_get_op_info:
 * @c: the context
 * @reserved:
 *
 * Return information about the last operation.  The caller has to
 * free the string.  NULL is returned if there is not previous
 * operation available or the operation has not yet finished.
 *
 * Here is a sample information we return:
 * <literal>
 * <![CDATA[
 * <GnupgOperationInfo>
 *   <signature>
 *     <detached/> <!-- or cleartext or standard -->
 *     <algo>17</algo>
 *     <hashalgo>2</hashalgo>
 *     <micalg>pgp-sha1</micalg>
 *     <sigclass>01</sigclass>
 *     <created>9222222</created>
 *     <fpr>121212121212121212</fpr>
 *   </signature>
 * </GnupgOperationInfo>
 * ]]>
 * </literal>
 * Return value: NULL for no info available or an XML string
 **/
char *
gpgme_get_op_info (GpgmeCtx ctx, int reserved)
{
  if (!ctx || reserved || !ctx->op_info)
    return NULL;  /* Invalid value.  */

  return _gpgme_data_get_as_string (ctx->op_info);
}


/* Store the data object INFO with the operation info in the context
   CTX.  INFO is consumed.  Subsequent calls append the data.  */
void
_gpgme_set_op_info (GpgmeCtx ctx, GpgmeData info)
{
  assert (ctx);

  if (!ctx->op_info)
    ctx->op_info = info;
  else
    {
      char *info_mem = 0;
      size_t info_len;

      info_mem = gpgme_data_release_and_get_mem (info, &info_len);
      _gpgme_data_append (ctx->op_info, info_mem, info_len);
    }
}


GpgmeError
gpgme_set_protocol (GpgmeCtx ctx, GpgmeProtocol protocol)
{
  if (protocol != GPGME_PROTOCOL_OpenPGP && protocol != GPGME_PROTOCOL_CMS)
    return GPGME_Invalid_Value;

  ctx->protocol = protocol;
  return 0;
}


GpgmeProtocol
gpgme_get_protocol (GpgmeCtx ctx)
{
  return ctx->protocol;
}


const char *
gpgme_get_protocol_name (GpgmeProtocol protocol)
{
  switch (protocol)
    {
    case GPGME_PROTOCOL_OpenPGP:
      return "OpenPGP";

    case GPGME_PROTOCOL_CMS:
      return "CMS";

    default:
      return NULL;
    }
}

/**
 * gpgme_set_armor:
 * @ctx: the context
 * @yes: boolean value to set or clear that flag
 *
 * Enable or disable the use of an ascii armor for all output.
 **/
void
gpgme_set_armor (GpgmeCtx ctx, int yes)
{
  if (!ctx)
    return;
  ctx->use_armor = yes;
}


/**
 * gpgme_get_armor:
 * @ctx: the context
 *
 * Return the state of the armor flag which can be changed using
 * gpgme_set_armor().
 *
 * Return value: Boolean whether armor mode is to be used.
 **/
int
gpgme_get_armor (GpgmeCtx ctx)
{
  return ctx && ctx->use_armor;
}


/**
 * gpgme_set_textmode:
 * @ctx: the context
 * @yes: boolean flag whether textmode should be enabled
 *
 * Enable or disable the use of the special textmode.  Textmode is for example
 * used for the RFC2015 signatures; note that the updated RFC 3156 mandates
 * that the MUA does some preparations so that textmode is not needed anymore.
 **/
void
gpgme_set_textmode (GpgmeCtx ctx, int yes)
{
  if (!ctx)
    return;
  ctx->use_textmode = yes;
}

/**
 * gpgme_get_textmode:
 * @ctx: the context
 *
 * Return the state of the textmode flag which can be changed using
 * gpgme_set_textmode().
 *
 * Return value: Boolean whether textmode is to be used.
 **/
int
gpgme_get_textmode (GpgmeCtx ctx)
{
  return ctx && ctx->use_textmode;
}


/**
 * gpgme_set_include_certs:
 * @ctx: the context
 *
 * Set the number of certifications to include in an S/MIME message.
 * The default is 1 (only the cert of the sender).  -1 means all certs,
 * and -2 means all certs except the root cert.
 *
 * Return value: Boolean whether textmode is to be used.
 **/
void
gpgme_set_include_certs (GpgmeCtx ctx, int nr_of_certs)
{
  if (nr_of_certs < -2)
    ctx->include_certs = -2;
  else
    ctx->include_certs = nr_of_certs;
}


/**
 * gpgme_get_include_certs:
 * @ctx: the context
 *
 * Get the number of certifications to include in an S/MIME message.
 *
 * Return value: Boolean whether textmode is to be used.
 **/
int
gpgme_get_include_certs (GpgmeCtx ctx)
{
  return ctx->include_certs;
}


/**
 * gpgme_set_keylist_mode:
 * @ctx: the context
 * @mode: listing mode
 *
 * This function changes the default behaviour of the keylisting
 * functions.  mode is a bitwise-OR of the GPGME_KEYLIST_* flags.
 * The default mode is GPGME_KEYLIST_MODE_LOCAL.
 *
 * Return value: GPGME_Invalid_Value if ctx is not a context or mode
 * not a valid mode.
 **/
GpgmeError
gpgme_set_keylist_mode (GpgmeCtx ctx, int mode)
{
  if (!ctx)
    return GPGME_Invalid_Value;

  if (!((mode & GPGME_KEYLIST_MODE_LOCAL)
	|| (mode & GPGME_KEYLIST_MODE_EXTERN)
	|| (mode & GPGME_KEYLIST_MODE_SIGS)))
     return GPGME_Invalid_Value;

  ctx->keylist_mode = mode;
  return 0;
}


/**
 * gpgme_get_keylist_mode:
 * @ctx: the context
 *
 * This function ch the default behaviour of the keylisting functions.
 * Defines values for @mode are: %0 = normal, %1 = fast listing without
 * information about key validity.
 *
 * Return value: 0 if ctx is not a valid context, or the current mode.
 * Note that 0 is never a valid mode.
 **/
int
gpgme_get_keylist_mode (GpgmeCtx ctx)
{
  if (!ctx)
    return 0;
  return ctx->keylist_mode;
}


/**
 * gpgme_set_passphrase_cb:
 * @ctx: the context
 * @cb: A callback function
 * @cb_value: The value passed to the callback function
 *
 * This function sets a callback function to be used to pass a passphrase
 * to gpg. The preferred way to handle this is by using the gpg-agent, but
 * because that beast is not ready for real use, you can use this passphrase
 * thing.
 *
 * The callback function is defined as:
 * <literal>
 * typedef const char *(*GpgmePassphraseCb)(void*cb_value,
 *                                          const char *desc,
 *                                          void **r_hd);
 * </literal>
 * and called whenever gpgme needs a passphrase. DESC will have a nice
 * text, to be used to prompt for the passphrase and R_HD is just a parameter
 * to be used by the callback it self.  Because the callback returns a const
 * string, the callback might want to know when it can release resources
 * assocated with that returned string; gpgme helps here by calling this
 * passphrase callback with an DESC of %NULL as soon as it does not need
 * the returned string anymore.  The callback function might then choose
 * to release resources depending on R_HD.
 *
 **/
void
gpgme_set_passphrase_cb (GpgmeCtx ctx, GpgmePassphraseCb cb, void *cb_value)
{
  if (ctx)
    {
      ctx->passphrase_cb = cb;
      ctx->passphrase_cb_value = cb_value;
    }
}


/**
 * gpgme_get_passphrase_cb:
 * @ctx: the context
 * @r_cb: The current callback function
 * @r_cb_value: The current value passed to the callback function
 *
 * This function returns the callback function to be used to pass a passphrase
 * to the crypto engine.
 **/
void
gpgme_get_passphrase_cb (GpgmeCtx ctx, GpgmePassphraseCb *r_cb, void **r_cb_value)
{
  if (ctx)
    {
      if (r_cb)
	*r_cb = ctx->passphrase_cb;
      if (r_cb_value)
	*r_cb_value = ctx->passphrase_cb_value;
    }
  else
    {
      if (r_cb)
	*r_cb = NULL;
      if (r_cb_value)
	*r_cb_value = NULL;
    }
}


/**
 * gpgme_set_progress_cb:
 * @ctx: the context
 * @cb: A callback function
 * @cb_value: The value passed to the callback function
 *
 * This function sets a callback function to be used as a progress indicator.
 *
 * The callback function is defined as:
 * <literal>
 * typedef void (*GpgmeProgressCb) (void *cb_value,
 *                                  const char *what, int type,
 *                                  int curretn, int total);
 * </literal>
 * For details on the progress events, see the entry for the PROGRESS
 * status in the file doc/DETAILS of the GnuPG distribution.
 **/
void
gpgme_set_progress_cb (GpgmeCtx ctx, GpgmeProgressCb cb, void *cb_value)
{
  if (ctx)
    {
      ctx->progress_cb = cb;
      ctx->progress_cb_value = cb_value;
    }
}


/**
 * gpgme_get_progress_cb:
 * @ctx: the context
 * @r_cb: The current callback function
 * @r_cb_value: The current value passed to the callback function
 *
 * This function returns the callback function to be used as a
 * progress indicator.
 **/
void
gpgme_get_progress_cb (GpgmeCtx ctx, GpgmeProgressCb *r_cb, void **r_cb_value)
{
  if (ctx)
    {
      if (r_cb)
	*r_cb = ctx->progress_cb;
      if (r_cb_value)
	*r_cb_value = ctx->progress_cb_value;
    }
  else
    {
      if (r_cb)
	*r_cb = NULL;
      if (r_cb_value)
	*r_cb_value = NULL;
    }
}


/**
 * gpgme_set_io_cbs:
 * @ctx: the context
 * @register_io_cb: A callback function
 * @register_hook_value: The value passed to the callback function
 * @remove_io_cb: Another callback function
 *
 **/
void
gpgme_set_io_cbs (GpgmeCtx ctx, struct GpgmeIOCbs *io_cbs)
{
  if (!ctx)
    return;

  if (io_cbs)
    ctx->io_cbs = *io_cbs;
  else
    {
      ctx->io_cbs.add = NULL;
      ctx->io_cbs.add_priv = NULL;
      ctx->io_cbs.remove = NULL;
      ctx->io_cbs.event = NULL;
      ctx->io_cbs.event_priv = NULL;
    }
}


/**
 * gpgme_get_io_cbs:
 * @ctx: the context
 * @r_register_cb: The current register callback function
 * @r_register_cb_value: The current value passed to the
 * register callback function
 * @r_remove_cb: The current remove callback function
 *
 * This function returns the callback function to be used to pass a passphrase
 * to the crypto engine.
 **/
void
gpgme_get_io_cbs (GpgmeCtx ctx, struct GpgmeIOCbs *io_cbs)
{
  if (ctx && io_cbs)
    *io_cbs = ctx->io_cbs;
}


const char *
gpgme_pubkey_algo_name (GpgmePubKeyAlgo algo)
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
gpgme_hash_algo_name (GpgmeHashAlgo algo)
{
  switch (algo)
    {
    case GPGME_MD_MD5:
      return "MD5";

    case GPGME_MD_SHA1:
      return "SHA1";

    case GPGME_MD_RMD160:
      return "RMD160";

    case GPGME_MD_MD2:
      return "MD2";

    case GPGME_MD_TIGER:
      return "TIGER";

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
      return "CRC32-RFC1510";

    case GPGME_MD_CRC24_RFC2440:
      return "CRC24-RFC2440";

    default:
      return NULL;
    }
}

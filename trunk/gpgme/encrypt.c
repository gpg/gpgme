/* encrypt.c -  encrypt functions
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

#define SKIP_TOKEN_OR_RETURN(a) do { \
    while (*(a) && *(a) != ' ') (a)++; \
    while (*(a) == ' ') (a)++; \
    if (!*(a)) \
        return; /* oops */ \
} while (0)

struct encrypt_result_s
{
  int no_recipients;
  GpgmeData xmlinfo;
};

void
_gpgme_release_encrypt_result (EncryptResult result)
{
  if (!result)
    return;
  gpgme_data_release (result->xmlinfo);
  xfree (result);
}

/* 
 * Parse the args and save the information 
 * in an XML structure.
 * With args of NULL the xml structure is closed.
 */
static void
append_xml_encinfo (GpgmeData *rdh, char *args)
{
  GpgmeData dh;
  char helpbuf[100];

  if (!*rdh)
    {
      if (gpgme_data_new (rdh))
	return; /* FIXME: We are ignoring out-of-core.  */
      dh = *rdh;
      _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
  else
    {
      dh = *rdh;
      _gpgme_data_append_string (dh, "  </encryption>\n");
    }

  if (!args)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
      return;
    }

  _gpgme_data_append_string (dh, "  <encryption>\n"
			     "    <error>\n"
			     "      <invalidRecipient/>\n");
    
  sprintf (helpbuf, "      <reason>%d</reason>\n", atoi (args));
  _gpgme_data_append_string (dh, helpbuf);
  SKIP_TOKEN_OR_RETURN (args);

  _gpgme_data_append_string (dh, "      <name>");
  _gpgme_data_append_percentstring_for_xml (dh, args);
  _gpgme_data_append_string (dh, "</name>\n"
			     "    </error>\n");
}


static void
encrypt_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  if (ctx->out_of_core)
    return;
  if (!ctx->result.encrypt)
    {
      ctx->result.encrypt = xtrycalloc (1, sizeof *ctx->result.encrypt);
      if (!ctx->result.encrypt)
	{
	  ctx->out_of_core = 1;
	  return;
	}
    }

  switch (code)
    {
    case STATUS_EOF:
      if (ctx->result.encrypt->xmlinfo)
	{
	  append_xml_encinfo (&ctx->result.encrypt->xmlinfo, NULL);
	  _gpgme_set_op_info (ctx, ctx->result.encrypt->xmlinfo);
	  ctx->result.encrypt->xmlinfo = NULL;
        }
      break;

    case STATUS_INV_RECP:
      append_xml_encinfo (&ctx->result.encrypt->xmlinfo, args);
      break;

    case STATUS_NO_RECP:
      ctx->result.encrypt->no_recipients = 1; /* i.e. no usable ones */
      break;

    default:
      break;
    }
}


GpgmeError
gpgme_op_encrypt_start (GpgmeCtx ctx, GpgmeRecipients recp, GpgmeData plain,
			GpgmeData ciph)
{
  int err = 0;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_release_result (ctx);
  ctx->out_of_core = 0;

  /* Do some checks.  */
  if (!gpgme_recipients_count (recp))
    {
      /* Fixme: In this case we should do symmentric encryption.  */
      err = mk_error (No_Recipients);
      goto leave;
    }

  /* Create an engine object.  */
  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    goto leave;

  _gpgme_engine_set_status_handler (ctx->engine, encrypt_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  /* Check the supplied data */
  if (gpgme_data_get_type (plain) == GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (No_Data);
      goto leave;
    }
  _gpgme_data_set_mode (plain, GPGME_DATA_MODE_OUT);
  if (!ciph || gpgme_data_get_type (ciph) != GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (Invalid_Value);
      goto leave;
    }
  _gpgme_data_set_mode (ciph, GPGME_DATA_MODE_IN);

  err = _gpgme_engine_op_encrypt (ctx->engine, recp, plain, ciph, ctx->use_armor);


  if (!err)	/* And kick off the process.  */
    err = _gpgme_engine_start (ctx->engine, ctx);

 leave:
  if (err)
    {
      ctx->pending = 0; 
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


/**
 * gpgme_op_encrypt:
 * @c: The context
 * @recp: A set of recipients 
 * @in: plaintext input
 * @out: ciphertext output
 * 
 * This function encrypts @in to @out for all recipients from
 * @recp.  Other parameters are take from the context @c.
 * The function does wait for the result.
 * 
 * Return value:  0 on success or an errorcode. 
 **/
GpgmeError
gpgme_op_encrypt (GpgmeCtx ctx, GpgmeRecipients recp,
		  GpgmeData plain, GpgmeData cipher)
{
  int err = gpgme_op_encrypt_start (ctx, recp, plain, cipher);
  if (!err)
    {
      gpgme_wait (ctx, 1);
      if (!ctx->result.encrypt)
	err = mk_error (General_Error);
      else if (ctx->out_of_core)
	err = mk_error (Out_Of_Core);
      else
	{
	  if (ctx->result.encrypt->no_recipients) 
	    err = mk_error (No_Recipients);
        }
      /* Old gpg versions don't return status info for invalid
	 recipients, so we simply check whether we got any output at
	 all, and if not we assume that we don't have valid
	 recipients.  */
      if (!err && gpgme_data_get_type (cipher) == GPGME_DATA_TYPE_NONE)
	err = mk_error (No_Recipients);
    }
  return err;
}








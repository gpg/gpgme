/* import.c -  encrypt functions
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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


struct import_result_s
{
  GpgmeData xmlinfo;
};


void
_gpgme_release_import_result (ImportResult result)
{
  if (!result)
    return;
  gpgme_data_release (result->xmlinfo);
  xfree (result);
}


/* Parse the args and append the information to the XML structure in
   the data buffer.  With args of NULL the xml structure is
   closed.  */
static void
append_xml_impinfo (GpgmeData *rdh, GpgStatusCode code, char *args)
{
#define MAX_IMPORTED_FIELDS 14
  static char *imported_fields[MAX_IMPORTED_FIELDS]
    = { "keyid", "username", 0 };
  static char *import_res_fields[MAX_IMPORTED_FIELDS]
    = { "count", "no_user_id", "imported", "imported_rsa",
	"unchanged", "n_uids", "n_subk", "n_sigs", "s_sigsn_revoc",
	"sec_read", "sec_imported", "sec_dups", "skipped_new", 0 };
  char *field[MAX_IMPORTED_FIELDS];
  char **field_name = 0;
  GpgmeData dh;
  int i;

  /* Verify that we can use the args.  */
  if (code != STATUS_EOF)
    {
      if (!args)
	return;

      if (code == STATUS_IMPORTED)
	field_name = imported_fields;
      else if (code == STATUS_IMPORT_RES)
	field_name = import_res_fields;
      else
	return;

      for (i = 0; field_name[i]; i++)
	{
	  field[i] = args;
	  if (field_name[i + 1])
	    {
	      args = strchr (args, ' ');
	      if (!args)
		return;  /* Invalid line.  */
	      *args++ = '\0';
	    }
	}
    }

  /* Initialize the data buffer if necessary.  */
  if (!*rdh)
    {
      if (gpgme_data_new (rdh))
        return; /* FIXME: We are ignoring out-of-core.  */
      dh = *rdh;
      _gpgme_data_append_string (dh, "<GnupgOperationInfo>\n");
    }
  else
    dh = *rdh;
    
  if (code == STATUS_EOF)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
    }
  else
    {
      if (code == STATUS_IMPORTED)
	_gpgme_data_append_string (dh, "  <import>\n");
      else if (code == STATUS_IMPORT_RES)
	_gpgme_data_append_string (dh, "  <importResult>\n");

      for (i = 0; field_name[i]; i++)
	{
	  _gpgme_data_append_string (dh, "    <");
	  _gpgme_data_append_string (dh, field_name[i]);
	  _gpgme_data_append_string (dh, ">");
	  _gpgme_data_append_string (dh, field[i]);
	  _gpgme_data_append_string (dh, "</");
	  _gpgme_data_append_string (dh, field_name[i]);
	  _gpgme_data_append_string (dh, ">\n");
	}

      if (code == STATUS_IMPORTED)
	_gpgme_data_append_string (dh, "  </import>\n");
      else if (code == STATUS_IMPORT_RES)
	_gpgme_data_append_string (dh, "  </importResult>\n");
    }
}


static void
import_status_handler (GpgmeCtx ctx, GpgStatusCode code, char *args)
{
  if (ctx->error)
    return;
  test_and_allocate_result (ctx, import);

  switch (code)
    {
    case STATUS_EOF:
      if (ctx->result.import->xmlinfo)
        {
          append_xml_impinfo (&ctx->result.import->xmlinfo, code, NULL);
          _gpgme_set_op_info (ctx, ctx->result.import->xmlinfo);
          ctx->result.import->xmlinfo = NULL;
        }
      /* XXX Calculate error value.  */
      break;

    case STATUS_IMPORTED:
    case STATUS_IMPORT_RES:
      append_xml_impinfo (&ctx->result.import->xmlinfo, code, args);
      break;

    default:
      break;
    }
}


GpgmeError
gpgme_op_import_start (GpgmeCtx ctx, GpgmeData keydata)
{
  int err = 0;

  fail_on_pending_request (ctx);
  ctx->pending = 1;

  _gpgme_engine_release (ctx->engine);
  ctx->engine = NULL;
  err = _gpgme_engine_new (ctx->use_cms ? GPGME_PROTOCOL_CMS
			   : GPGME_PROTOCOL_OpenPGP, &ctx->engine);
  if (err)
    goto leave;

  /* Check the supplied data */
  if (gpgme_data_get_type (keydata) == GPGME_DATA_TYPE_NONE)
    {
      err = mk_error (No_Data);
      goto leave;
    }
  _gpgme_data_set_mode (keydata, GPGME_DATA_MODE_OUT);

  _gpgme_engine_set_status_handler (ctx->engine, import_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  _gpgme_engine_op_import (ctx->engine, keydata);

  if (!err)
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
 * gpgme_op_import:
 * @c: Context 
 * @keydata: Data object
 * 
 * Import all key material from @keydata into the key database.
 * 
 * Return value: o on success or an error code.
 **/
GpgmeError
gpgme_op_import (GpgmeCtx ctx, GpgmeData keydata)
{
  GpgmeError err = gpgme_op_import_start (ctx, keydata);
  if (!err)
    {
      gpgme_wait (ctx, 1);
      err = ctx->error;
    }
  return err;
}

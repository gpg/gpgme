/* import.c - Import functions.
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
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "context.h"
#include "ops.h"


struct import_result
{
  int nr_imported;
  int nr_considered;
  GpgmeData xmlinfo;
};
typedef struct import_result *ImportResult;

static void
release_import_result (void *hook)
{
  ImportResult result = (ImportResult) hook;

  if (result->xmlinfo)
    gpgme_data_release (result->xmlinfo);
}


/* Parse the args and append the information to the XML structure in
   the data buffer.  With args of NULL the xml structure is
   closed.  */
static void
append_xml_impinfo (GpgmeData *rdh, GpgmeStatusCode code, char *args)
{
#define MAX_IMPORTED_FIELDS 14
  static const char *const imported_fields[MAX_IMPORTED_FIELDS]
    = { "keyid", "username", 0 };
  static const char *const imported_fields_x509[MAX_IMPORTED_FIELDS]
    = { "fpr", 0 };
  static const char *const import_res_fields[MAX_IMPORTED_FIELDS]
    = { "count", "no_user_id", "imported", "imported_rsa",
	"unchanged", "n_uids", "n_subk", "n_sigs", "s_sigsn_revoc",
	"sec_read", "sec_imported", "sec_dups", "skipped_new", 0 };
  const char *field[MAX_IMPORTED_FIELDS];
  const char *const *field_name = 0;
  GpgmeData dh;
  int i;

  /* Verify that we can use the args.  */
  if (code != GPGME_STATUS_EOF)
    {
      if (!args)
	return;

      if (code == GPGME_STATUS_IMPORTED)
	field_name = imported_fields;
      else if (code == GPGME_STATUS_IMPORT_RES)
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
      
      /* gpgsm does not print a useful user ID and uses a fingerprint
         instead of the key ID. */
      if (code == GPGME_STATUS_IMPORTED && field[0] && strlen (field[0]) > 16)
        field_name = imported_fields_x509;
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
    
  if (code == GPGME_STATUS_EOF)
    {
      /* Just close the XML containter.  */
      _gpgme_data_append_string (dh, "</GnupgOperationInfo>\n");
    }
  else
    {
      if (code == GPGME_STATUS_IMPORTED)
	_gpgme_data_append_string (dh, "  <import>\n");
      else if (code == GPGME_STATUS_IMPORT_RES)
	_gpgme_data_append_string (dh, "  <importResult>\n");

      for (i = 0; field_name[i]; i++)
	{
	  _gpgme_data_append_string (dh, "    <");
          _gpgme_data_append_string (dh, field_name[i]);
	  _gpgme_data_append_string (dh, ">");
	  _gpgme_data_append_string_for_xml (dh, field[i]);
	  _gpgme_data_append_string (dh, "</");
	  _gpgme_data_append_string (dh, field_name[i]);
	  _gpgme_data_append_string (dh, ">\n");
	}

      if (code == GPGME_STATUS_IMPORTED)
	_gpgme_data_append_string (dh, "  </import>\n");
      else if (code == GPGME_STATUS_IMPORT_RES)
	_gpgme_data_append_string (dh, "  </importResult>\n");
    }
}


static GpgmeError
import_status_handler (GpgmeCtx ctx, GpgmeStatusCode code, char *args)
{
  GpgmeError err;
  ImportResult result;

  err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, (void **) &result,
			       sizeof (*result), release_import_result);
  if (err)
    return err;

  switch (code)
    {
    case GPGME_STATUS_EOF:
      if (result->xmlinfo)
        {
          append_xml_impinfo (&result->xmlinfo, code, NULL);
          _gpgme_set_op_info (ctx, result->xmlinfo);
          result->xmlinfo = NULL;
        }
      /* XXX Calculate error value.  */
      break;

    case GPGME_STATUS_IMPORTED:
      result->nr_imported++;
      append_xml_impinfo (&result->xmlinfo, code, args);
      break;

    case GPGME_STATUS_IMPORT_RES:
      result->nr_considered = strtol (args, 0, 0);
      append_xml_impinfo (&result->xmlinfo, code, args);
      break;

    default:
      break;
    }
  return 0;
}


static GpgmeError
_gpgme_op_import_start (GpgmeCtx ctx, int synchronous, GpgmeData keydata)
{
  int err = 0;

  err = _gpgme_op_reset (ctx, synchronous);
  if (err)
    goto leave;

  /* Check the supplied data */
  if (!keydata)
    {
      err = GPGME_No_Data;
      goto leave;
    }

  _gpgme_engine_set_status_handler (ctx->engine, import_status_handler, ctx);
  _gpgme_engine_set_verbosity (ctx->engine, ctx->verbosity);

  err = _gpgme_engine_op_import (ctx->engine, keydata);

 leave:
  if (err)
    {
      ctx->pending = 0;
      _gpgme_engine_release (ctx->engine);
      ctx->engine = NULL;
    }
  return err;
}


GpgmeError
gpgme_op_import_start (GpgmeCtx ctx, GpgmeData keydata)
{
  return _gpgme_op_import_start (ctx, 0, keydata);
}

/**
 * gpgme_op_import:
 * @c: Context 
 * @keydata: Data object
 * @nr: Will contain number of considered keys.
 * 
 * Import all key material from @keydata into the key database.
 * 
 * Return value: 0 on success or an error code.
 **/
GpgmeError
gpgme_op_import_ext (GpgmeCtx ctx, GpgmeData keydata, int *nr)
{
  GpgmeError err = _gpgme_op_import_start (ctx, 1, keydata);
  if (!err)
    err = _gpgme_wait_one (ctx);
  if (!err && nr)
    {
      ImportResult result;

      err = _gpgme_op_data_lookup (ctx, OPDATA_IMPORT, (void **) &result,
				   -1, NULL);
      if (result)
	*nr = result->nr_considered;
      else
	*nr = 0;
    }
  return err;
}

GpgmeError
gpgme_op_import (GpgmeCtx ctx, GpgmeData keydata)
{
  return gpgme_op_import_ext (ctx, keydata, 0);
}

/* engine.c - GPGME engine support.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2006 g10 Code GmbH
 
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "gpgme.h"
#include "util.h"
#include "sema.h"
#include "ops.h"

#include "engine.h"
#include "engine-backend.h"


struct engine
{
  struct engine_ops *ops;
  void *engine;
};


static struct engine_ops *engine_ops[] =
  {
    &_gpgme_engine_ops_gpg,		/* OpenPGP.  */
#ifdef ENABLE_GPGSM
    &_gpgme_engine_ops_gpgsm		/* CMS.  */
#else
    NULL
#endif
  };


/* The engine info.  */
static gpgme_engine_info_t engine_info;
DEFINE_STATIC_LOCK (engine_info_lock);


/* Get the file name of the engine for PROTOCOL.  */
static const char *
engine_get_file_name (gpgme_protocol_t proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_file_name)
    return (*engine_ops[proto]->get_file_name) ();
  else
    return NULL;
}


/* Get a malloced string containing the version number of the engine
   for PROTOCOL.  */
static char *
engine_get_version (gpgme_protocol_t proto, const char *file_name)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_version)
    return (*engine_ops[proto]->get_version) (file_name);
  else
    return NULL;
}


/* Get the required version number of the engine for PROTOCOL.  */
static const char *
engine_get_req_version (gpgme_protocol_t proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_req_version)
    return (*engine_ops[proto]->get_req_version) ();
  else
    return NULL;
}


/* Verify the version requirement for the engine for PROTOCOL.  */
gpgme_error_t
gpgme_engine_check_version (gpgme_protocol_t proto)
{
  gpgme_error_t err;
  gpgme_engine_info_t info;
  int result;

  LOCK (engine_info_lock);
  info = engine_info;
  if (!info)
    {
      /* Make sure it is initialized.  */
      UNLOCK (engine_info_lock);
      err = gpgme_get_engine_info (&info);
      if (err)
	return err;

      LOCK (engine_info_lock);
    }

  while (info && info->protocol != proto)
    info = info->next;

  if (!info)
    result = 0;
  else
    result = _gpgme_compare_versions (info->version,
				      info->req_version);

  UNLOCK (engine_info_lock);
  return result ? 0 : gpg_error (GPG_ERR_INV_ENGINE);
}


/* Release the engine info INFO.  */
void
_gpgme_engine_info_release (gpgme_engine_info_t info)
{
  while (info)
    {
      gpgme_engine_info_t next_info = info->next;

      assert (info->file_name);
      free (info->file_name);
      if (info->home_dir)
	free (info->home_dir);
      if (info->version)
	free (info->version);
      free (info);
      info = next_info;
    }
}


/* Get the information about the configured and installed engines.  A
   pointer to the first engine in the statically allocated linked list
   is returned in *INFO.  If an error occurs, it is returned.  The
   returned data is valid until the next gpgme_set_engine_info.  */
gpgme_error_t
gpgme_get_engine_info (gpgme_engine_info_t *info)
{
  LOCK (engine_info_lock);
  if (!engine_info)
    {
      gpgme_engine_info_t *lastp = &engine_info;
      gpgme_protocol_t proto_list[] = { GPGME_PROTOCOL_OpenPGP,
					GPGME_PROTOCOL_CMS };
      unsigned int proto;

      for (proto = 0; proto < DIM (proto_list); proto++)
	{
	  const char *ofile_name = engine_get_file_name (proto_list[proto]);
	  char *file_name;

	  if (!ofile_name)
	    continue;

	  file_name = strdup (ofile_name);

	  *lastp = malloc (sizeof (*engine_info));
	  if (!*lastp || !file_name)
	    {
	      int saved_errno = errno;

	      _gpgme_engine_info_release (engine_info);
	      engine_info = NULL;

	      if (file_name)
		free (file_name);

	      UNLOCK (engine_info_lock);
	      return gpg_error_from_errno (saved_errno);
	    }

	  (*lastp)->protocol = proto_list[proto];
	  (*lastp)->file_name = file_name;
	  (*lastp)->home_dir = NULL;
	  (*lastp)->version = engine_get_version (proto_list[proto], NULL);
	  (*lastp)->req_version = engine_get_req_version (proto_list[proto]);
	  (*lastp)->next = NULL;
	  lastp = &(*lastp)->next;
	}
    }

  *info = engine_info;
  UNLOCK (engine_info_lock);
  return 0;
}


/* Get a deep copy of the engine info and return it in INFO.  */
gpgme_error_t
_gpgme_engine_info_copy (gpgme_engine_info_t *r_info)
{
  gpgme_error_t err = 0;
  gpgme_engine_info_t info;
  gpgme_engine_info_t new_info;
  gpgme_engine_info_t *lastp;

  LOCK (engine_info_lock);
  info = engine_info;
  if (!info)
    {
      /* Make sure it is initialized.  */
      UNLOCK (engine_info_lock);
      err = gpgme_get_engine_info (&info);
      if (err)
	return err;

      LOCK (engine_info_lock);
    }

  new_info = NULL;
  lastp = &new_info;

  while (info)
    {
      char *file_name;
      char *home_dir;
      char *version;

      assert (info->file_name);
      file_name = strdup (info->file_name);

      if (info->home_dir)
	{
	  home_dir = strdup (info->home_dir);
	  if (!home_dir)
	    err = gpg_error_from_errno (errno);
	}
      else
	home_dir = NULL;

      if (info->version)
	{
	  version = strdup (info->version);
	  if (!version)
	    err = gpg_error_from_errno (errno);
	}
      else
	version = NULL;

      *lastp = malloc (sizeof (*engine_info));
      if (!*lastp || !file_name || err)
	{
	  int saved_errno = errno;

	  _gpgme_engine_info_release (new_info);

	  if (file_name)
	    free (file_name);
	  if (home_dir)
	    free (home_dir);
	  if (version)
	    free (version);

	  UNLOCK (engine_info_lock);
	  return gpg_error_from_errno (saved_errno);
	}

      (*lastp)->protocol = info->protocol;
      (*lastp)->file_name = file_name;
      (*lastp)->home_dir = home_dir;
      (*lastp)->version = version;
      (*lastp)->req_version = info->req_version;
      (*lastp)->next = NULL;
      lastp = &(*lastp)->next;

      info = info->next;
    }

  *r_info = new_info;
  UNLOCK (engine_info_lock);
  return 0;
}


/* Set the engine info for the info list INFO, protocol PROTO, to the
   file name FILE_NAME and the home directory HOME_DIR.  */
gpgme_error_t
_gpgme_set_engine_info (gpgme_engine_info_t info, gpgme_protocol_t proto,
			const char *file_name, const char *home_dir)
{
  char *new_file_name;
  char *new_home_dir;

  /* FIXME: Use some PROTO_MAX definition.  */
  if (proto > DIM (engine_ops))
    return gpg_error (GPG_ERR_INV_VALUE);

  while (info && info->protocol != proto)
    info = info->next;

  if (!info)
    return gpg_error (GPG_ERR_INV_ENGINE);

  /* Prepare new members.  */
  if (file_name)
    new_file_name = strdup (file_name);
  else
    {
      const char *ofile_name = engine_get_file_name (proto);
      assert (ofile_name);
      new_file_name = strdup (ofile_name);
    }
  if (!new_file_name)
    return gpg_error_from_errno (errno);

  if (home_dir)
    {
      new_home_dir = strdup (home_dir);
      if (!new_home_dir)
	{
	  free (new_file_name);
	  return gpg_error_from_errno (errno);
	}
    }
  else
    new_home_dir = NULL;

  /* Remove the old members.  */
  assert (info->file_name);
  free (info->file_name);
  if (info->home_dir)
    free (info->home_dir);
  if (info->version)
    free (info->version);

  /* Install the new members.  */
  info->file_name = new_file_name;
  info->home_dir = new_home_dir;
  info->version = engine_get_version (proto, new_file_name);

  return 0;
}


/* Set the default engine info for the protocol PROTO to the file name
   FILE_NAME and the home directory HOME_DIR.  */
gpgme_error_t
gpgme_set_engine_info (gpgme_protocol_t proto,
		       const char *file_name, const char *home_dir)
{
  gpgme_error_t err;
  gpgme_engine_info_t info;

  LOCK (engine_info_lock);
  info = engine_info;
  if (!info)
    {
      /* Make sure it is initialized.  */
      UNLOCK (engine_info_lock);
      err = gpgme_get_engine_info (&info);
      if (err)
	return err;

      LOCK (engine_info_lock);
    }

  err = _gpgme_set_engine_info (info, proto, file_name, home_dir);
  UNLOCK (engine_info_lock);
  return err;
}


gpgme_error_t
_gpgme_engine_new (gpgme_engine_info_t info, engine_t *r_engine)
{
  engine_t engine;

  if (!info->file_name || !info->version)
    return gpg_error (GPG_ERR_INV_ENGINE);

  engine = calloc (1, sizeof *engine);
  if (!engine)
    return gpg_error_from_errno (errno);

  engine->ops = engine_ops[info->protocol];
  if (engine->ops->new)
    {
      gpgme_error_t err;
      err = (*engine->ops->new) (&engine->engine,
				 info->file_name, info->home_dir);
      if (err)
	{
	  free (engine);
	  return err;
	}
    }
  else
    engine->engine = NULL;

  *r_engine = engine;
  return 0;
}


gpgme_error_t
_gpgme_engine_reset (engine_t engine)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->reset)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->reset) (engine->engine);
}


void
_gpgme_engine_release (engine_t engine)
{
  if (!engine)
    return;

  if (engine->ops->release)
    (*engine->ops->release) (engine->engine);
  free (engine);
}


void
_gpgme_engine_set_status_handler (engine_t engine,
				  engine_status_handler_t fnc, void *fnc_value)
{
  if (!engine)
    return;

  if (engine->ops->set_status_handler)
    (*engine->ops->set_status_handler) (engine->engine, fnc, fnc_value);
}


gpgme_error_t
_gpgme_engine_set_command_handler (engine_t engine,
				   engine_command_handler_t fnc,
				   void *fnc_value,
				   gpgme_data_t linked_data)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_command_handler)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_command_handler) (engine->engine,
					      fnc, fnc_value, linked_data);
}

gpgme_error_t
_gpgme_engine_set_colon_line_handler (engine_t engine,
				      engine_colon_line_handler_t fnc,
				      void *fnc_value)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_colon_line_handler)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_colon_line_handler) (engine->engine,
						 fnc, fnc_value);
}

gpgme_error_t
_gpgme_engine_set_locale (engine_t engine, int category,
			  const char *value)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_locale)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_locale) (engine->engine, category, value);
}

gpgme_error_t
_gpgme_engine_op_decrypt (engine_t engine, gpgme_data_t ciph,
			  gpgme_data_t plain)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->decrypt)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->decrypt) (engine->engine, ciph, plain);
}

gpgme_error_t
_gpgme_engine_op_delete (engine_t engine, gpgme_key_t key,
			 int allow_secret)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->delete)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->delete) (engine->engine, key, allow_secret);
}


gpgme_error_t
_gpgme_engine_op_edit (engine_t engine, int type, gpgme_key_t key,
		       gpgme_data_t out, gpgme_ctx_t ctx /* FIXME */)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->edit)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->edit) (engine->engine, type, key, out, ctx);
}


gpgme_error_t
_gpgme_engine_op_encrypt (engine_t engine, gpgme_key_t recp[],
			  gpgme_encrypt_flags_t flags,
			  gpgme_data_t plain, gpgme_data_t ciph, int use_armor)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->encrypt)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->encrypt) (engine->engine, recp, flags, plain, ciph,
				  use_armor);
}


gpgme_error_t
_gpgme_engine_op_encrypt_sign (engine_t engine, gpgme_key_t recp[],
			       gpgme_encrypt_flags_t flags,
			       gpgme_data_t plain, gpgme_data_t ciph,
			       int use_armor, gpgme_ctx_t ctx /* FIXME */)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->encrypt_sign)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->encrypt_sign) (engine->engine, recp, flags,
				       plain, ciph, use_armor, ctx);
}


gpgme_error_t
_gpgme_engine_op_export (engine_t engine, const char *pattern,
			 unsigned int reserved, gpgme_data_t keydata,
			 int use_armor)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->export)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->export) (engine->engine, pattern, reserved,
				 keydata, use_armor);
}


gpgme_error_t
_gpgme_engine_op_export_ext (engine_t engine, const char *pattern[],
			     unsigned int reserved, gpgme_data_t keydata,
			     int use_armor)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->export_ext)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->export_ext) (engine->engine, pattern, reserved,
				     keydata, use_armor);
}


gpgme_error_t
_gpgme_engine_op_genkey (engine_t engine, gpgme_data_t help_data,
			 int use_armor, gpgme_data_t pubkey,
			 gpgme_data_t seckey)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->genkey)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->genkey) (engine->engine, help_data, use_armor,
				 pubkey, seckey);
}


gpgme_error_t
_gpgme_engine_op_import (engine_t engine, gpgme_data_t keydata)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->import)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->import) (engine->engine, keydata);
}


gpgme_error_t
_gpgme_engine_op_keylist (engine_t engine, const char *pattern,
			  int secret_only, gpgme_keylist_mode_t mode)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keylist)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keylist) (engine->engine, pattern, secret_only, mode);
}


gpgme_error_t
_gpgme_engine_op_keylist_ext (engine_t engine, const char *pattern[],
			      int secret_only, int reserved,
			      gpgme_keylist_mode_t mode)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keylist_ext)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keylist_ext) (engine->engine, pattern, secret_only,
				      reserved, mode);
}


gpgme_error_t
_gpgme_engine_op_sign (engine_t engine, gpgme_data_t in, gpgme_data_t out,
		       gpgme_sig_mode_t mode, int use_armor,
		       int use_textmode, int include_certs,
		       gpgme_ctx_t ctx /* FIXME */)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->sign)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->sign) (engine->engine, in, out, mode, use_armor,
			       use_textmode, include_certs, ctx);
}


gpgme_error_t
_gpgme_engine_op_trustlist (engine_t engine, const char *pattern)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->trustlist)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->trustlist) (engine->engine, pattern);
}


gpgme_error_t
_gpgme_engine_op_verify (engine_t engine, gpgme_data_t sig,
			 gpgme_data_t signed_text, gpgme_data_t plaintext)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->verify)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->verify) (engine->engine, sig, signed_text, plaintext);
}


void
_gpgme_engine_set_io_cbs (engine_t engine, gpgme_io_cbs_t io_cbs)
{
  if (!engine)
    return;

  (*engine->ops->set_io_cbs) (engine->engine, io_cbs);
}


void
_gpgme_engine_io_event (engine_t engine,
			gpgme_event_io_t type, void *type_data)
{
  if (!engine)
    return;

  (*engine->ops->io_event) (engine->engine, type, type_data);
}


gpgme_error_t
_gpgme_engine_cancel (engine_t engine)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->cancel)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->cancel) (engine->engine);
}

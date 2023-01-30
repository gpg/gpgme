/* engine.c - GPGME engine support.
 * Copyright (C) 2000 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2006, 2009, 2010 g10 Code GmbH
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
#include "debug.h"

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
    &_gpgme_engine_ops_gpgsm,		/* CMS.  */
    &_gpgme_engine_ops_gpgconf,		/* gpg-conf.  */
    &_gpgme_engine_ops_assuan,		/* Low-Level Assuan.  */
    &_gpgme_engine_ops_g13,		/* Crypto VFS.  */
#ifdef ENABLE_UISERVER
    &_gpgme_engine_ops_uiserver,	/* UI-Server.  */
#else
    NULL,
#endif
    &_gpgme_engine_ops_spawn
  };


/* The engine info.  */
static gpgme_engine_info_t engine_info;
DEFINE_STATIC_LOCK (engine_info_lock);

/* If non-NULL, the minimal version required for all engines.  */
static char *engine_minimal_version;



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


/* Get the standard home dir of the engine for PROTOCOL.  */
static const char *
engine_get_home_dir (gpgme_protocol_t proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_home_dir)
    return (*engine_ops[proto]->get_home_dir) ();
  else
    return NULL;
}


/* Get a malloced string containing the version number of the engine
 * for PROTOCOL.  If this function returns NULL for a valid protocol,
 * it should be assumed that the engine is a pseudo engine. */
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


/* Get the required version number of the engine for PROTOCOL.  This
 * may be NULL. */
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
  return result ? 0 : trace_gpg_error (GPG_ERR_INV_ENGINE);
}


/* Release the engine info INFO.  */
void
_gpgme_engine_info_release (gpgme_engine_info_t info)
{
  while (info)
    {
      gpgme_engine_info_t next_info = info->next;

      if (info->file_name)
        free (info->file_name);
      if (info->home_dir)
	free (info->home_dir);
      if (info->version)
	free (info->version);
      free (info);
      info = next_info;
    }
}


/* This is an internal function to set a mimimal required version.
 * This function must only be called by gpgme_set_global_flag.
 * Returns 0 on success.  */
int
_gpgme_set_engine_minimal_version (const char *value)
{
  free (engine_minimal_version);
  if (value)
    {
      engine_minimal_version = strdup (value);
      return !engine_minimal_version;
    }
  else
    {
      engine_minimal_version = NULL;
      return 0;
    }
}


/* Get the information about the configured and installed engines.  A
   pointer to the first engine in the statically allocated linked list
   is returned in *INFO.  If an error occurs, it is returned.  The
   returned data is valid until the next gpgme_set_engine_info.  */
gpgme_error_t
gpgme_get_engine_info (gpgme_engine_info_t *info)
{
  gpgme_error_t err;

  LOCK (engine_info_lock);
  if (!engine_info)
    {
      gpgme_engine_info_t *lastp = &engine_info;
      gpgme_protocol_t proto_list[] = { GPGME_PROTOCOL_OpenPGP,
					GPGME_PROTOCOL_CMS,
					GPGME_PROTOCOL_GPGCONF,
					GPGME_PROTOCOL_ASSUAN,
					GPGME_PROTOCOL_G13,
					GPGME_PROTOCOL_UISERVER,
                                        GPGME_PROTOCOL_SPAWN    };
      unsigned int proto;

      err = 0;
      for (proto = 0; proto < DIM (proto_list); proto++)
	{
	  const char *ofile_name = engine_get_file_name (proto_list[proto]);
	  const char *ohome_dir  = engine_get_home_dir (proto_list[proto]);
          char *version = engine_get_version (proto_list[proto], NULL);
	  char *file_name;
	  char *home_dir;

	  if (!ofile_name)
	    continue;

	  file_name = strdup (ofile_name);
          if (!file_name)
            err = gpg_error_from_syserror ();

          if (ohome_dir)
            {
              home_dir = strdup (ohome_dir);
              if (!home_dir && !err)
                err = gpg_error_from_syserror ();
            }
          else
            home_dir = NULL;

	  *lastp = calloc (1, sizeof (*engine_info));
          if (!*lastp && !err)
            err = gpg_error_from_syserror ();

          /* Check against the optional minimal engine version.  */
          if (!err && version && engine_minimal_version
              && !_gpgme_compare_versions (version, engine_minimal_version))
            {
              err = gpg_error (GPG_ERR_ENGINE_TOO_OLD);
            }

          /* Now set the dummy version for pseudo engines.  */
          if (!err && !version)
            {
              version = strdup ("1.0.0");
              if (!version)
                err = gpg_error_from_syserror ();
            }

	  if (err)
	    {
	      _gpgme_engine_info_release (engine_info);
	      engine_info = NULL;

	      if (file_name)
		free (file_name);
	      if (home_dir)
		free (home_dir);
	      if (version)
		free (version);

	      UNLOCK (engine_info_lock);
	      return err;
	    }

	  (*lastp)->protocol = proto_list[proto];
	  (*lastp)->file_name = file_name;
	  (*lastp)->home_dir = home_dir;
	  (*lastp)->version = version;
	  (*lastp)->req_version = engine_get_req_version (proto_list[proto]);
	  if (!(*lastp)->req_version)
            (*lastp)->req_version = "1.0.0"; /* Dummy for pseudo engines. */
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
      if (!file_name)
        err = gpg_error_from_syserror ();

      if (info->home_dir)
	{
	  home_dir = strdup (info->home_dir);
	  if (!home_dir && !err)
	    err = gpg_error_from_syserror ();
	}
      else
	home_dir = NULL;

      if (info->version)
	{
	  version = strdup (info->version);
	  if (!version && !err)
	    err = gpg_error_from_syserror ();
	}
      else
	version = NULL;

      *lastp = malloc (sizeof (*engine_info));
      if (!*lastp && !err)
        err = gpg_error_from_syserror ();

      if (err)
	{
	  _gpgme_engine_info_release (new_info);
	  if (file_name)
	    free (file_name);
	  if (home_dir)
	    free (home_dir);
	  if (version)
	    free (version);

	  UNLOCK (engine_info_lock);
	  return err;
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
  char *new_version;

  /* FIXME: Use some PROTO_MAX definition.  */
  if (proto > DIM (engine_ops))
    return gpg_error (GPG_ERR_INV_VALUE);

  while (info && info->protocol != proto)
    info = info->next;

  if (!info)
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

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
    return gpg_error_from_syserror ();

  if (home_dir)
    {
      new_home_dir = strdup (home_dir);
      if (!new_home_dir)
	{
	  free (new_file_name);
	  return gpg_error_from_syserror ();
	}
    }
  else
    {
      const char *ohome_dir = engine_get_home_dir (proto);
      if (ohome_dir)
        {
          new_home_dir = strdup (ohome_dir);
          if (!new_home_dir)
            {
              free (new_file_name);
              return gpg_error_from_syserror ();
            }
        }
      else
        new_home_dir = NULL;
    }

  new_version = engine_get_version (proto, new_file_name);
  if (!new_version)
    {
      new_version = strdup ("1.0.0"); /* Fake one for dummy entries.  */
      if (!new_version)
        {
          free (new_file_name);
          free (new_home_dir);
          return gpg_error_from_syserror ();
        }
    }

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
  info->version = new_version;

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
    return trace_gpg_error (GPG_ERR_INV_ENGINE);

  engine = calloc (1, sizeof *engine);
  if (!engine)
    return gpg_error_from_syserror ();

  engine->ops = engine_ops[info->protocol];
  if (engine->ops->new)
    {
      gpgme_error_t err;
      err = (*engine->ops->new) (&engine->engine,
				 info->file_name, info->home_dir,
                                 info->version);
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


/* Set a status callback which is used to monitor the status values
 * before they are passed to a handler set with
 * _gpgme_engine_set_status_handler.  */
void
_gpgme_engine_set_status_cb (engine_t engine,
                             gpgme_status_cb_t cb, void *cb_value)
{
  if (!engine)
    return;

  if (engine->ops->set_status_cb)
    (*engine->ops->set_status_cb) (engine->engine, cb, cb_value);
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
				   void *fnc_value)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_command_handler)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_command_handler) (engine->engine, fnc, fnc_value);
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
_gpgme_engine_set_protocol (engine_t engine, gpgme_protocol_t protocol)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_protocol)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_protocol) (engine->engine, protocol);
}


/* Pass information about the current context to the engine.  The
 * engine may use this context to retrieve context specific flags.
 * Important: The engine is required to immediately copy the required
 * flags to its own context!
 *
 * This function will eventually be used to reduce the number of
 * explicit passed flags.  */
void
_gpgme_engine_set_engine_flags (engine_t engine, gpgme_ctx_t ctx)
{
  if (!engine)
    return;

  if (!engine->ops->set_engine_flags)
    return;

  (*engine->ops->set_engine_flags) (engine->engine, ctx);
}


gpgme_error_t
_gpgme_engine_op_decrypt (engine_t engine,
                          gpgme_decrypt_flags_t flags,
                          gpgme_data_t ciph,
			  gpgme_data_t plain, int export_session_key,
                          const char *override_session_key,
                          int auto_key_retrieve)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->decrypt)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->decrypt) (engine->engine, flags, ciph, plain,
                                  export_session_key, override_session_key,
                                  auto_key_retrieve);
}


gpgme_error_t
_gpgme_engine_op_delete (engine_t engine, gpgme_key_t key,
			 unsigned int flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->delete)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->delete) (engine->engine, key, flags);
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
                          const char *recpstring,
			  gpgme_encrypt_flags_t flags,
			  gpgme_data_t plain, gpgme_data_t ciph, int use_armor)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->encrypt)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->encrypt) (engine->engine, recp, recpstring,
                                  flags, plain, ciph, use_armor);
}


gpgme_error_t
_gpgme_engine_op_encrypt_sign (engine_t engine, gpgme_key_t recp[],
                               const char *recpstring,
			       gpgme_encrypt_flags_t flags,
			       gpgme_data_t plain, gpgme_data_t ciph,
			       int use_armor, gpgme_ctx_t ctx /* FIXME */)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->encrypt_sign)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->encrypt_sign) (engine->engine, recp, recpstring,
                                       flags, plain, ciph, use_armor, ctx);
}


gpgme_error_t
_gpgme_engine_op_export (engine_t engine, const char *pattern,
			 gpgme_export_mode_t mode, gpgme_data_t keydata,
			 int use_armor)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->export)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->export) (engine->engine, pattern, mode,
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
_gpgme_engine_op_genkey (engine_t engine,
                         const char *userid, const char *algo,
                         unsigned long reserved, unsigned long expires,
                         gpgme_key_t key, unsigned int flags,
                         gpgme_data_t help_data,
			 unsigned int extraflags,
                         gpgme_data_t pubkey, gpgme_data_t seckey)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->genkey)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->genkey) (engine->engine,
                                 userid, algo, reserved, expires, key, flags,
                                 help_data, extraflags,
				 pubkey, seckey);
}


gpgme_error_t
_gpgme_engine_op_keysign (engine_t engine, gpgme_key_t key, const char *userid,
                          unsigned long expires, unsigned int flags,
                          gpgme_ctx_t ctx)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keysign)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keysign) (engine->engine,
                                  key, userid, expires, flags, ctx);
}


gpgme_error_t
_gpgme_engine_op_revsig (engine_t engine, gpgme_key_t key, gpgme_key_t signing_key,
                         const char *userid, unsigned int flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->revsig)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->revsig) (engine->engine, key, signing_key, userid, flags);
}


gpgme_error_t
_gpgme_engine_op_tofu_policy (engine_t engine,
                              gpgme_key_t key,  gpgme_tofu_policy_t policy)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->tofu_policy)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->tofu_policy) (engine->engine, key, policy);
}


gpgme_error_t
_gpgme_engine_op_import (engine_t engine, gpgme_data_t keydata,
                         gpgme_key_t *keyarray, const char *keyids[],
                         const char *import_filter, const char *key_origin)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->import)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->import) (engine->engine, keydata, keyarray, keyids,
                                 import_filter, key_origin);
}


gpgme_error_t
_gpgme_engine_op_keylist (engine_t engine, const char *pattern,
			  int secret_only, gpgme_keylist_mode_t mode,
			  int engine_flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keylist)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keylist) (engine->engine, pattern, secret_only, mode,
                                  engine_flags);
}


gpgme_error_t
_gpgme_engine_op_keylist_ext (engine_t engine, const char *pattern[],
			      int secret_only, int reserved,
			      gpgme_keylist_mode_t mode, int engine_flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keylist_ext)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keylist_ext) (engine->engine, pattern, secret_only,
				      reserved, mode, engine_flags);
}


gpgme_error_t
_gpgme_engine_op_keylist_data (engine_t engine, gpgme_keylist_mode_t mode,
			       gpgme_data_t data)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->keylist_data)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->keylist_data) (engine->engine, mode, data);
}


gpgme_error_t
_gpgme_engine_op_sign (engine_t engine, gpgme_data_t in, gpgme_data_t out,
		       gpgme_sig_mode_t flags, int use_armor,
		       int use_textmode, int include_certs,
		       gpgme_ctx_t ctx /* FIXME */)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->sign)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->sign) (engine->engine, in, out, flags, use_armor,
			       use_textmode, include_certs, ctx);
}


gpgme_error_t
_gpgme_engine_op_trustlist (engine_t engine, const char *pattern)
{
  (void)pattern;

  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  return gpg_error (GPG_ERR_NOT_IMPLEMENTED);
}


gpgme_error_t
_gpgme_engine_op_verify (engine_t engine, gpgme_verify_flags_t flags,
                         gpgme_data_t sig, gpgme_data_t signed_text,
                         gpgme_data_t plaintext, gpgme_ctx_t ctx)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->verify)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->verify) (engine->engine, flags, sig, signed_text,
                                 plaintext, ctx);
}


gpgme_error_t
_gpgme_engine_op_getauditlog (engine_t engine, gpgme_data_t output,
                              unsigned int flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->getauditlog)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->getauditlog) (engine->engine, output, flags);
}


gpgme_error_t
_gpgme_engine_op_assuan_transact (engine_t engine,
                                  const char *command,
                                  gpgme_assuan_data_cb_t data_cb,
                                  void *data_cb_value,
                                  gpgme_assuan_inquire_cb_t inq_cb,
                                  void *inq_cb_value,
                                  gpgme_assuan_status_cb_t status_cb,
                                  void *status_cb_value)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->opassuan_transact)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->opassuan_transact) (engine->engine,
                                            command,
                                            data_cb, data_cb_value,
                                            inq_cb, inq_cb_value,
                                            status_cb, status_cb_value);
}


gpgme_error_t
_gpgme_engine_op_conf_load (engine_t engine, gpgme_conf_comp_t *conf_p)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->conf_load)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->conf_load) (engine->engine, conf_p);
}


gpgme_error_t
_gpgme_engine_op_conf_save (engine_t engine, gpgme_conf_comp_t conf)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->conf_save)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->conf_save) (engine->engine, conf);
}


gpgme_error_t
_gpgme_engine_op_conf_dir (engine_t engine, const char *what, char **result)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->conf_dir)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->conf_dir) (engine->engine, what, result);
}


gpgme_error_t
_gpgme_engine_op_query_swdb (engine_t engine,
                             const char *name, const char *iversion,
                             gpgme_query_swdb_result_t result)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->query_swdb)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->query_swdb) (engine->engine, name, iversion, result);
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


/* Cancel the session and the pending operation if any.  */
gpgme_error_t
_gpgme_engine_cancel (engine_t engine)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->cancel)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->cancel) (engine->engine);
}


/* Cancel the pending operation, but not the complete session.  */
gpgme_error_t
_gpgme_engine_cancel_op (engine_t engine)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->cancel_op)
    return 0;

  return (*engine->ops->cancel_op) (engine->engine);
}


/* Change the passphrase for KEY.  */
gpgme_error_t
_gpgme_engine_op_passwd (engine_t engine, gpgme_key_t key,
                         unsigned int flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->passwd)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->passwd) (engine->engine, key, flags);
}


/* Set the pinentry mode for ENGINE to MODE.  */
gpgme_error_t
_gpgme_engine_set_pinentry_mode (engine_t engine, gpgme_pinentry_mode_t mode)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->set_pinentry_mode)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->set_pinentry_mode) (engine->engine, mode);
}


gpgme_error_t
_gpgme_engine_op_spawn (engine_t engine,
                        const char *file, const char *argv[],
                        gpgme_data_t datain,
                        gpgme_data_t dataout, gpgme_data_t dataerr,
                        unsigned int flags)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->opspawn)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->opspawn) (engine->engine, file, argv,
                                  datain, dataout, dataerr, flags);
}

gpgme_error_t
_gpgme_engine_op_setexpire (engine_t engine, gpgme_key_t key,
                            unsigned long expires, const char *subfprs,
                            unsigned int reserved)
{
  if (!engine)
    return gpg_error (GPG_ERR_INV_VALUE);

  if (!engine->ops->setexpire)
    return gpg_error (GPG_ERR_NOT_IMPLEMENTED);

  return (*engine->ops->setexpire) (engine->engine, key, expires, subfprs, reserved);
}

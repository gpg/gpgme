/* engine.c - GPGME engine support.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "gpgme.h"
#include "util.h"
#include "sema.h"
#include "ops.h"

#include "engine.h"
#include "engine-backend.h"


struct engine_object_s
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


/* Get the file name of the engine for PROTOCOL.  */
static const char *
engine_get_file_name (GpgmeProtocol proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_file_name)
    return (*engine_ops[proto]->get_file_name) ();
  else
    return NULL;
}


/* Get the version number of the engine for PROTOCOL.  */
static const char *
engine_get_version (GpgmeProtocol proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_version)
    return (*engine_ops[proto]->get_version) ();
  else
    return NULL;
}


/* Get the required version number of the engine for PROTOCOL.  */
static const char *
engine_get_req_version (GpgmeProtocol proto)
{
  if (proto > DIM (engine_ops))
    return NULL;

  if (engine_ops[proto] && engine_ops[proto]->get_req_version)
    return (*engine_ops[proto]->get_req_version) ();
  else
    return NULL;
}


/* Verify the version requirement for the engine for PROTOCOL.  */
GpgmeError
gpgme_engine_check_version (GpgmeProtocol proto)
{
  return _gpgme_compare_versions (engine_get_version (proto),
				  engine_get_req_version (proto))
    ? 0 : GPGME_Invalid_Engine;
}


/* Get the information about the configured and installed engines.  A
   pointer to the first engine in the statically allocated linked list
   is returned in *INFO.  If an error occurs, it is returned.  */
GpgmeError
gpgme_get_engine_info (GpgmeEngineInfo *info)
{
  static GpgmeEngineInfo engine_info;
  DEFINE_STATIC_LOCK (engine_info_lock);

  LOCK (engine_info_lock);
  if (!engine_info)
    {
      GpgmeEngineInfo *lastp = &engine_info;
      GpgmeProtocol proto_list[] = { GPGME_PROTOCOL_OpenPGP,
				     GPGME_PROTOCOL_CMS };
      int proto;

      for (proto = 0; proto < DIM (proto_list); proto++)
	{
	  const char *file_name = engine_get_file_name (proto_list[proto]);

	  if (!file_name)
	    continue;

	  *lastp = malloc (sizeof (*engine_info));
	  if (!*lastp)
	    {
	      while (engine_info)
		{
		  GpgmeEngineInfo next_info = engine_info->next;
		  free (engine_info);
		  engine_info = next_info;
		}
	      UNLOCK (engine_info_lock);
	      return GPGME_Out_Of_Core;
	    }

	  (*lastp)->protocol = proto_list[proto];
	  (*lastp)->file_name = file_name;
	  (*lastp)->version = engine_get_version (proto_list[proto]);
	  (*lastp)->req_version = engine_get_req_version (proto_list[proto]);
	  lastp = &(*lastp)->next;
	}
    }
  UNLOCK (engine_info_lock);
  *info = engine_info;
  return 0;
}


GpgmeError
_gpgme_engine_new (GpgmeProtocol proto, EngineObject *r_engine)
{
  EngineObject engine;

  const char *file_name;
  const char *version;

  if (proto > DIM (engine_ops))
    return GPGME_Invalid_Value;

  if (!engine_ops[proto])
    return GPGME_Invalid_Engine;

  file_name = engine_get_file_name (proto);
  version = engine_get_version (proto);
  if (!file_name || !version)
    return GPGME_Invalid_Engine;

  engine = calloc (1, sizeof *engine);
  if (!engine)
    return GPGME_Out_Of_Core;

  engine->ops = engine_ops[proto];
  if (engine_ops[proto]->new)
    {
      GpgmeError err = (*engine_ops[proto]->new) (&engine->engine);
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


void
_gpgme_engine_release (EngineObject engine)
{
  if (!engine)
    return;

  if (engine->ops->release)
    (*engine->ops->release) (engine->engine);
  free (engine);
}


void
_gpgme_engine_set_verbosity (EngineObject engine, int verbosity)
{
  if (!engine)
    return;

  if (engine->ops->set_verbosity)
    (*engine->ops->set_verbosity) (engine->engine, verbosity);
}


void
_gpgme_engine_set_status_handler (EngineObject engine,
				  EngineStatusHandler fnc, void *fnc_value)
{
  if (!engine)
    return;

  if (engine->ops->set_status_handler)
    (*engine->ops->set_status_handler) (engine->engine, fnc, fnc_value);
}


GpgmeError
_gpgme_engine_set_command_handler (EngineObject engine,
				   EngineCommandHandler fnc, void *fnc_value,
				   GpgmeData linked_data)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->set_command_handler)
    return GPGME_Not_Implemented;

  return (*engine->ops->set_command_handler) (engine->engine,
					      fnc, fnc_value, linked_data);
}

GpgmeError _gpgme_engine_set_colon_line_handler (EngineObject engine,
						 EngineColonLineHandler fnc,
						 void *fnc_value)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->set_colon_line_handler)
    return GPGME_Not_Implemented;

  return (*engine->ops->set_colon_line_handler) (engine->engine,
						 fnc, fnc_value);
}

GpgmeError
_gpgme_engine_op_decrypt (EngineObject engine, GpgmeData ciph, GpgmeData plain)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->decrypt)
    return GPGME_Not_Implemented;

  return (*engine->ops->decrypt) (engine->engine, ciph, plain);
}

GpgmeError
_gpgme_engine_op_delete (EngineObject engine, GpgmeKey key, int allow_secret)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->delete)
    return GPGME_Not_Implemented;

  return (*engine->ops->delete) (engine->engine, key, allow_secret);
}


GpgmeError
_gpgme_engine_op_edit (EngineObject engine, GpgmeKey key, GpgmeData out,
		       GpgmeCtx ctx /* FIXME */)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->edit)
    return GPGME_Not_Implemented;

  return (*engine->ops->edit) (engine->engine, key, out, ctx);
}


GpgmeError
_gpgme_engine_op_encrypt (EngineObject engine, GpgmeRecipients recp,
			  GpgmeData plain, GpgmeData ciph, int use_armor)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->encrypt)
    return GPGME_Not_Implemented;

  return (*engine->ops->encrypt) (engine->engine, recp, plain, ciph,
				  use_armor);
}


GpgmeError
_gpgme_engine_op_encrypt_sign (EngineObject engine, GpgmeRecipients recp,
			       GpgmeData plain, GpgmeData ciph, int use_armor,
			       GpgmeCtx ctx /* FIXME */)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->encrypt_sign)
    return GPGME_Not_Implemented;

  return (*engine->ops->encrypt_sign) (engine->engine, recp, plain, ciph,
				       use_armor, ctx);
}


GpgmeError
_gpgme_engine_op_export (EngineObject engine, GpgmeRecipients recp,
			 GpgmeData keydata, int use_armor)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->export)
    return GPGME_Not_Implemented;

  return (*engine->ops->export) (engine->engine, recp, keydata,
				 use_armor);
}


GpgmeError
_gpgme_engine_op_genkey (EngineObject engine, GpgmeData help_data,
			 int use_armor, GpgmeData pubkey, GpgmeData seckey)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->genkey)
    return GPGME_Not_Implemented;

  return (*engine->ops->genkey) (engine->engine, help_data, use_armor,
				 pubkey, seckey);
}


GpgmeError
_gpgme_engine_op_import (EngineObject engine, GpgmeData keydata)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->import)
    return GPGME_Not_Implemented;

  return (*engine->ops->import) (engine->engine, keydata);
}


GpgmeError
_gpgme_engine_op_keylist (EngineObject engine, const char *pattern,
			  int secret_only, int keylist_mode)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->keylist)
    return GPGME_Not_Implemented;

  return (*engine->ops->keylist) (engine->engine, pattern, secret_only,
				  keylist_mode);
}


GpgmeError
_gpgme_engine_op_keylist_ext (EngineObject engine, const char *pattern[],
			      int secret_only, int reserved, int keylist_mode)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->keylist_ext)
    return GPGME_Not_Implemented;

  return (*engine->ops->keylist_ext) (engine->engine, pattern, secret_only,
				      reserved, keylist_mode);
}


GpgmeError
_gpgme_engine_op_sign (EngineObject engine, GpgmeData in, GpgmeData out,
		       GpgmeSigMode mode, int use_armor,
		       int use_textmode, int include_certs,
		       GpgmeCtx ctx /* FIXME */)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->sign)
    return GPGME_Not_Implemented;

  return (*engine->ops->sign) (engine->engine, in, out, mode, use_armor,
			       use_textmode, include_certs, ctx);
}


GpgmeError
_gpgme_engine_op_trustlist (EngineObject engine, const char *pattern)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->trustlist)
    return GPGME_Not_Implemented;

  return (*engine->ops->trustlist) (engine->engine, pattern);
}


GpgmeError
_gpgme_engine_op_verify (EngineObject engine, GpgmeData sig,
			 GpgmeData signed_text, GpgmeData plaintext)
{
  if (!engine)
    return GPGME_Invalid_Value;

  if (!engine->ops->verify)
    return GPGME_Not_Implemented;

  return (*engine->ops->verify) (engine->engine, sig, signed_text, plaintext);
}


void
_gpgme_engine_set_io_cbs (EngineObject engine,
			  struct GpgmeIOCbs *io_cbs)
{
  if (!engine)
    return;

  (*engine->ops->set_io_cbs) (engine->engine, io_cbs);
}


void
_gpgme_engine_io_event (EngineObject engine,
			GpgmeEventIO type, void *type_data)
{
  if (!engine)
    return;

  (*engine->ops->io_event) (engine->engine, type, type_data);
}

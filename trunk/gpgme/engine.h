/* engine.h -  GPGME engine interface.
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

#ifndef ENGINE_H
#define ENGINE_H

#include "gpgme.h"
 
struct engine_object_s;
typedef struct engine_object_s *EngineObject;

typedef gpgme_error_t (*EngineStatusHandler) (void *priv,
					      gpgme_status_code_t code,
					      char *args);
typedef gpgme_error_t (*EngineColonLineHandler) (void *priv, char *line);
typedef gpgme_error_t (*EngineCommandHandler) (void *priv,
					       gpgme_status_code_t code,
					       const char *keyword,
					       const char **result);

gpgme_error_t _gpgme_engine_new (gpgme_protocol_t proto,
				 EngineObject *r_engine);
void _gpgme_engine_release (EngineObject engine);
void _gpgme_engine_set_status_handler (EngineObject engine,
				       EngineStatusHandler fnc,
				       void *fnc_value);
gpgme_error_t _gpgme_engine_set_command_handler (EngineObject engine,
					      EngineCommandHandler fnc,
					      void *fnc_value,
					      gpgme_data_t data);
gpgme_error_t _gpgme_engine_set_colon_line_handler (EngineObject engine,
						 EngineColonLineHandler fnc,
						 void *fnc_value);
gpgme_error_t _gpgme_engine_op_decrypt (EngineObject engine,
					gpgme_data_t ciph,
					gpgme_data_t plain);
gpgme_error_t _gpgme_engine_op_delete (EngineObject engine, gpgme_key_t key,
				       int allow_secret);
gpgme_error_t _gpgme_engine_op_edit (EngineObject engine, gpgme_key_t key,
				     gpgme_data_t out,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_encrypt (EngineObject engine,
					gpgme_recipients_t recp,
					gpgme_data_t plain, gpgme_data_t ciph,
					int use_armor);
gpgme_error_t _gpgme_engine_op_encrypt_sign (EngineObject engine,
					     gpgme_recipients_t recp,
					     gpgme_data_t plain,
					     gpgme_data_t ciph,
					     int use_armor,
					     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_export (EngineObject engine,
				       gpgme_recipients_t recp,
				       gpgme_data_t keydata, int use_armor);
gpgme_error_t _gpgme_engine_op_genkey (EngineObject engine,
				       gpgme_data_t help_data,
				       int use_armor, gpgme_data_t pubkey,
				       gpgme_data_t seckey);
gpgme_error_t _gpgme_engine_op_import (EngineObject engine,
				       gpgme_data_t keydata);
gpgme_error_t _gpgme_engine_op_keylist (EngineObject engine,
					const char *pattern,
					int secret_only,
					int keylist_mode);
gpgme_error_t _gpgme_engine_op_keylist_ext (EngineObject engine,
					    const char *pattern[],
					    int secret_only,
					    int reserved,
					    int keylist_mode);
gpgme_error_t _gpgme_engine_op_sign (EngineObject engine, gpgme_data_t in,
				     gpgme_data_t out, gpgme_sig_mode_t mode,
				     int use_armor, int use_textmode,
				     int include_certs,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_trustlist (EngineObject engine,
					  const char *pattern);
gpgme_error_t _gpgme_engine_op_verify (EngineObject engine, gpgme_data_t sig,
				       gpgme_data_t signed_text,
				       gpgme_data_t plaintext);

void _gpgme_engine_set_io_cbs (EngineObject engine,
			       gpgme_io_cbs_t io_cbs);
void _gpgme_engine_io_event (EngineObject engine,
			     gpgme_event_io_t type, void *type_data);

#endif /* ENGINE_H */

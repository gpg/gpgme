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
 
struct engine;
typedef struct engine *engine_t;

typedef gpgme_error_t (*engine_status_handler_t) (void *priv,
						  gpgme_status_code_t code,
						  char *args);
typedef gpgme_error_t (*engine_colon_line_handler_t) (void *priv, char *line);
typedef gpgme_error_t (*engine_command_handler_t) (void *priv,
						   gpgme_status_code_t code,
						   const char *keyword,
						   int fd);

gpgme_error_t _gpgme_engine_new (gpgme_protocol_t proto,
				 engine_t *r_engine,
				 const char *lc_ctype,
				 const char *lc_messages);
void _gpgme_engine_release (engine_t engine);
void _gpgme_engine_set_status_handler (engine_t engine,
				       engine_status_handler_t fnc,
				       void *fnc_value);
gpgme_error_t _gpgme_engine_set_command_handler (engine_t engine,
						 engine_command_handler_t fnc,
						 void *fnc_value,
						 gpgme_data_t data);
gpgme_error_t
_gpgme_engine_set_colon_line_handler (engine_t engine,
				      engine_colon_line_handler_t fnc,
				      void *fnc_value);
gpgme_error_t _gpgme_engine_op_decrypt (engine_t engine,
					gpgme_data_t ciph,
					gpgme_data_t plain);
gpgme_error_t _gpgme_engine_op_delete (engine_t engine, gpgme_key_t key,
				       int allow_secret);
gpgme_error_t _gpgme_engine_op_edit (engine_t engine, int type,
				     gpgme_key_t key, gpgme_data_t out,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_encrypt (engine_t engine,
					gpgme_key_t recp[],
					gpgme_encrypt_flags_t flags,
					gpgme_data_t plain, gpgme_data_t ciph,
					int use_armor);
gpgme_error_t _gpgme_engine_op_encrypt_sign (engine_t engine,
					     gpgme_key_t recp[],
					     gpgme_encrypt_flags_t flags,
					     gpgme_data_t plain,
					     gpgme_data_t ciph,
					     int use_armor,
					     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_export (engine_t engine, const char *pattern,
				       unsigned int reserved,
				       gpgme_data_t keydata, int use_armor);
gpgme_error_t _gpgme_engine_op_export_ext (engine_t engine,
					   const char *pattern[],
					   unsigned int reserved,
					   gpgme_data_t keydata,
					   int use_armor);
gpgme_error_t _gpgme_engine_op_genkey (engine_t engine,
				       gpgme_data_t help_data,
				       int use_armor, gpgme_data_t pubkey,
				       gpgme_data_t seckey);
gpgme_error_t _gpgme_engine_op_import (engine_t engine,
				       gpgme_data_t keydata);
gpgme_error_t _gpgme_engine_op_keylist (engine_t engine,
					const char *pattern,
					int secret_only,
					gpgme_keylist_mode_t mode);
gpgme_error_t _gpgme_engine_op_keylist_ext (engine_t engine,
					    const char *pattern[],
					    int secret_only,
					    int reserved,
					    gpgme_keylist_mode_t mode);
gpgme_error_t _gpgme_engine_op_sign (engine_t engine, gpgme_data_t in,
				     gpgme_data_t out, gpgme_sig_mode_t mode,
				     int use_armor, int use_textmode,
				     int include_certs,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_trustlist (engine_t engine,
					  const char *pattern);
gpgme_error_t _gpgme_engine_op_verify (engine_t engine, gpgme_data_t sig,
				       gpgme_data_t signed_text,
				       gpgme_data_t plaintext);

void _gpgme_engine_set_io_cbs (engine_t engine,
			       gpgme_io_cbs_t io_cbs);
void _gpgme_engine_io_event (engine_t engine,
			     gpgme_event_io_t type, void *type_data);

#endif /* ENGINE_H */

/* engine-backend.h -  A crypto backend for the engine interface.
   Copyright (C) 2002, 2003 g10 Code GmbH
 
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

#ifndef ENGINE_BACKEND_H
#define ENGINE_BACKEND_H

#include "engine.h"

/* FIXME: Correct check?  */
#ifdef GPGSM_PATH
#define ENABLE_GPGSM 1
#endif

struct engine_ops
{
  /* Static functions.  */
  const char *(*get_file_name) (void);
  const char *(*get_version) (void);
  const char *(*get_req_version) (void);
  gpgme_error_t (*new) (void **r_engine,
			const char *lc_ctype, const char *lc_messages);

  /* Member functions.  */
  void (*release) (void *engine);
  void (*set_status_handler) (void *engine, engine_status_handler_t fnc,
			      void *fnc_value);
  gpgme_error_t (*set_command_handler) (void *engine,
					engine_command_handler_t fnc,
					void *fnc_value, gpgme_data_t data);
  gpgme_error_t (*set_colon_line_handler) (void *engine,
					   engine_colon_line_handler_t fnc,
					   void *fnc_value);
  gpgme_error_t (*decrypt) (void *engine, gpgme_data_t ciph,
			    gpgme_data_t plain);
  gpgme_error_t (*delete) (void *engine, gpgme_key_t key, int allow_secret);
  gpgme_error_t (*edit) (void *engine, int type, gpgme_key_t key,
			 gpgme_data_t out, gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*encrypt) (void *engine, gpgme_key_t recp[],
			    gpgme_encrypt_flags_t flags,
			    gpgme_data_t plain, gpgme_data_t ciph,
			    int use_armor);
  gpgme_error_t (*encrypt_sign) (void *engine, gpgme_key_t recp[],
				 gpgme_encrypt_flags_t flags,
				 gpgme_data_t plain, gpgme_data_t ciph,
				 int use_armor, gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*export) (void *engine, const char *pattern,
			   unsigned int reserved, gpgme_data_t keydata,
			   int use_armor);
  gpgme_error_t (*export_ext) (void *engine, const char *pattern[],
			       unsigned int reserved, gpgme_data_t keydata,
			       int use_armor);
  gpgme_error_t (*genkey) (void *engine, gpgme_data_t help_data, int use_armor,
			   gpgme_data_t pubkey, gpgme_data_t seckey);
  gpgme_error_t (*import) (void *engine, gpgme_data_t keydata);
  gpgme_error_t (*keylist) (void *engine, const char *pattern,
			    int secret_only, gpgme_keylist_mode_t mode);
  gpgme_error_t (*keylist_ext) (void *engine, const char *pattern[],
				int secret_only, int reserved,
				gpgme_keylist_mode_t mode);
  gpgme_error_t (*sign) (void *engine, gpgme_data_t in, gpgme_data_t out,
			 gpgme_sig_mode_t mode, int use_armor,
			 int use_textmode,
			 int include_certs, gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*trustlist) (void *engine, const char *pattern);
  gpgme_error_t (*verify) (void *engine, gpgme_data_t sig,
			   gpgme_data_t signed_text,
			   gpgme_data_t plaintext);
  
  void (*set_io_cbs) (void *engine, gpgme_io_cbs_t io_cbs);
  void (*io_event) (void *engine, gpgme_event_io_t type, void *type_data);
};


extern struct engine_ops _gpgme_engine_ops_gpg;		/* OpenPGP.  */
#ifdef ENABLE_GPGSM
extern struct engine_ops _gpgme_engine_ops_gpgsm;	/* CMS.  */
#endif

#endif /* ENGINE_BACKEND_H */

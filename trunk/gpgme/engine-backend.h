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
  GpgmeError (*new) (void **r_engine);

  /* Member functions.  */
  void (*release) (void *engine);
  void (*set_status_handler) (void *engine, EngineStatusHandler fnc,
			      void *fnc_value);
  GpgmeError (*set_command_handler) (void *engine, EngineCommandHandler fnc,
				     void *fnc_value, GpgmeData data);
  GpgmeError (*set_colon_line_handler) (void *engine,
					EngineColonLineHandler fnc,
					void *fnc_value);
  GpgmeError (*decrypt) (void *engine, GpgmeData ciph, GpgmeData plain);
  GpgmeError (*delete) (void *engine, GpgmeKey key, int allow_secret);
  GpgmeError (*edit) (void *engine, GpgmeKey key, GpgmeData out,
			 GpgmeCtx ctx /* FIXME */);
  GpgmeError (*encrypt) (void *engine, GpgmeRecipients recp,
			    GpgmeData plain, GpgmeData ciph, int use_armor);
  GpgmeError (*encrypt_sign) (void *engine, GpgmeRecipients recp,
				  GpgmeData plain, GpgmeData ciph,
				  int use_armor, GpgmeCtx ctx /* FIXME */);
  GpgmeError (*export) (void *engine, GpgmeRecipients recp,
			   GpgmeData keydata, int use_armor);
  GpgmeError (*genkey) (void *engine, GpgmeData help_data, int use_armor,
			   GpgmeData pubkey, GpgmeData seckey);
  GpgmeError (*import) (void *engine, GpgmeData keydata);
  GpgmeError (*keylist) (void *engine, const char *pattern,
			    int secret_only, int keylist_mode);
  GpgmeError (*keylist_ext) (void *engine, const char *pattern[],
				 int secret_only, int reserved,
				int keylist_mode);
  GpgmeError (*sign) (void *engine, GpgmeData in, GpgmeData out,
			 GpgmeSigMode mode, int use_armor, int use_textmode,
			 int include_certs, GpgmeCtx ctx /* FIXME */);
  GpgmeError (*trustlist) (void *engine, const char *pattern);
  GpgmeError (*verify) (void *engine, GpgmeData sig, GpgmeData signed_text,
			   GpgmeData plaintext);
  
  void (*set_io_cbs) (void *engine, struct GpgmeIOCbs *io_cbs);
  void (*io_event) (void *engine, GpgmeEventIO type, void *type_data);
};


extern struct engine_ops _gpgme_engine_ops_gpg;		/* OpenPGP.  */
#ifdef ENABLE_GPGSM
extern struct engine_ops _gpgme_engine_ops_gpgsm;	/* CMS.  */
#endif

#endif /* ENGINE_BACKEND_H */


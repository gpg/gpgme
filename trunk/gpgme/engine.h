/* engine.h -  GPGME engine calling functions
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

#ifndef ENGINE_H
#define ENGINE_H

#include "types.h"
#include "rungpg.h"

const char *_gpgme_engine_get_path (GpgmeProtocol proto);
const char *_gpgme_engine_get_version (GpgmeProtocol proto);
GpgmeError gpgme_engine_check_version (GpgmeProtocol proto);
const char * _gpgme_engine_get_info (GpgmeProtocol proto);
GpgmeError _gpgme_engine_new (GpgmeProtocol proto, EngineObject *r_engine);
void _gpgme_engine_release (EngineObject engine);
void _gpgme_engine_set_status_handler (EngineObject engine,
				       GpgStatusHandler fnc, void *fnc_value);
GpgmeError _gpgme_engine_set_command_handler (EngineObject engine,
					      GpgCommandHandler fnc,
					      void *fnc_value);
GpgmeError _gpgme_engine_set_colon_line_handler (EngineObject gpg,
						 GpgColonLineHandler fnc,
						 void *fnc_value);
void _gpgme_engine_set_verbosity (EngineObject engine, int verbosity);
GpgmeError _gpgme_engine_op_decrypt (EngineObject engine, GpgmeData ciph,
				     GpgmeData plain);
GpgmeError _gpgme_engine_op_delete (EngineObject engine, GpgmeKey key,
				    int allow_secret);
GpgmeError _gpgme_engine_op_encrypt (EngineObject engine, GpgmeRecipients recp,
				     GpgmeData plain, GpgmeData ciph,
				     int use_armor);
GpgmeError _gpgme_engine_op_export (EngineObject engine, GpgmeRecipients recp,
				    GpgmeData keydata, int use_armor);
GpgmeError _gpgme_engine_op_genkey (EngineObject engine, GpgmeData help_data,
				    int use_armor);
GpgmeError _gpgme_engine_op_import (EngineObject engine, GpgmeData keydata);
GpgmeError _gpgme_engine_op_keylist (EngineObject engine, const char *pattern,
				     int secret_only,
				     int keylist_mode);
GpgmeError _gpgme_engine_op_sign (EngineObject engine, GpgmeData in,
				  GpgmeData out, GpgmeSigMode mode,
				  int use_armor, int use_textmode,
				  GpgmeCtx ctx /* FIXME */);
GpgmeError _gpgme_engine_op_trustlist (EngineObject engine,
				       const char *pattern);
GpgmeError _gpgme_engine_op_verify (EngineObject engine, GpgmeData sig,
				    GpgmeData text);
GpgmeError _gpgme_engine_start (EngineObject engine, void *opaque);

void _gpgme_engine_add_child_to_reap_list (void *buf, int buflen, pid_t pid);
void _gpgme_engine_housecleaning (void);

#endif /* ENGINE_H */

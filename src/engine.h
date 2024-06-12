/* engine.h - GPGME engine interface.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2010 g10 Code GmbH

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

#ifndef ENGINE_H
#define ENGINE_H

#include "gpgme.h"

/* Flags used by the EXTRAFLAGS arg of _gpgme_engine_op_genkey.  */
#define GENKEY_EXTRAFLAG_ARMOR      1
#define GENKEY_EXTRAFLAG_REVOKE     2
#define GENKEY_EXTRAFLAG_SETPRIMARY 4


struct engine;
typedef struct engine *engine_t;

typedef gpgme_error_t (*engine_status_handler_t) (void *priv,
						  gpgme_status_code_t code,
						  char *args);
typedef gpgme_error_t (*engine_colon_line_handler_t) (void *priv, char *line);
typedef gpgme_error_t (*engine_command_handler_t) (void *priv,
						   gpgme_status_code_t code,
						   const char *keyword,
						   int fd, int *processed);
typedef gpgme_error_t (*engine_assuan_result_cb_t) (void *priv,
                                                    gpgme_error_t result);

/* Helper for gpgme_set_global_flag.  */
int _gpgme_set_engine_minimal_version (const char *value);

/* Get a deep copy of the engine info and return it in INFO.  */
gpgme_error_t _gpgme_engine_info_copy (gpgme_engine_info_t *r_info);

/* Release the engine info INFO.  */
void _gpgme_engine_info_release (gpgme_engine_info_t info);

/* Set the engine info for the info list INFO, protocol PROTO, to the
   file name FILE_NAME and the home directory HOME_DIR.  */
gpgme_error_t _gpgme_set_engine_info (gpgme_engine_info_t info,
				      gpgme_protocol_t praoto,
				      const char *file_name,
				      const char *home_dir);


gpgme_error_t _gpgme_engine_new (gpgme_engine_info_t info,
				 engine_t *r_engine);
gpgme_error_t _gpgme_engine_reset (engine_t engine);

gpgme_error_t _gpgme_engine_set_locale (engine_t engine, int category,
					const char *value);
gpgme_error_t _gpgme_engine_set_protocol (engine_t engine,
					  gpgme_protocol_t protocol);
void _gpgme_engine_set_engine_flags (engine_t engine, gpgme_ctx_t ctx);
void _gpgme_engine_release (engine_t engine);
void _gpgme_engine_set_status_cb (engine_t engine,
                                  gpgme_status_cb_t cb, void *cb_value);
void _gpgme_engine_set_status_handler (engine_t engine,
				       engine_status_handler_t fnc,
				       void *fnc_value);
gpgme_error_t _gpgme_engine_set_command_handler (engine_t engine,
						 engine_command_handler_t fnc,
						 void *fnc_value);
gpgme_error_t
_gpgme_engine_set_colon_line_handler (engine_t engine,
				      engine_colon_line_handler_t fnc,
				      void *fnc_value);
gpgme_error_t _gpgme_engine_op_decrypt (engine_t engine,
                                        gpgme_decrypt_flags_t flags,
                                        gpgme_data_t ciph,
					gpgme_data_t plain,
                                        int export_session_key,
                                        const char *override_session_key,
                                        int auto_key_retrieve);
gpgme_error_t _gpgme_engine_op_delete (engine_t engine, gpgme_key_t key,
				       unsigned int flags);
gpgme_error_t _gpgme_engine_op_edit (engine_t engine, int type,
				     gpgme_key_t key, gpgme_data_t out,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_encrypt (engine_t engine,
					gpgme_key_t recp[],
                                        const char *recpstring,
					gpgme_encrypt_flags_t flags,
					gpgme_data_t plain, gpgme_data_t ciph,
					int use_armor);
gpgme_error_t _gpgme_engine_op_encrypt_sign (engine_t engine,
					     gpgme_key_t recp[],
                                             const char *recpstring,
					     gpgme_encrypt_flags_t flags,
					     gpgme_data_t plain,
					     gpgme_data_t ciph,
					     int use_armor,
					     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_export (engine_t engine, const char *pattern,
				       gpgme_export_mode_t mode,
				       gpgme_data_t keydata, int use_armor);
gpgme_error_t _gpgme_engine_op_export_ext (engine_t engine,
					   const char *pattern[],
					   gpgme_export_mode_t mode,
					   gpgme_data_t keydata,
					   int use_armor);
gpgme_error_t _gpgme_engine_op_genkey (engine_t engine,
                                       const char *userid, const char *algo,
                                       unsigned long reserved,
                                       unsigned long expires,
                                       gpgme_key_t key, unsigned int flags,
				       gpgme_data_t help_data,
				       unsigned int extraflags,
                                       gpgme_data_t pubkey,
				       gpgme_data_t seckey);
gpgme_error_t _gpgme_engine_op_keysign (engine_t engine,
                                        gpgme_key_t key, const char *userid,
                                        unsigned long expires,
                                        unsigned int flags,
                                        gpgme_ctx_t ctx);
gpgme_error_t _gpgme_engine_op_revsig (engine_t engine,
                                       gpgme_key_t key,
                                       gpgme_key_t signing_key,
                                       const char *userid,
                                       unsigned int flags);
gpgme_error_t _gpgme_engine_op_tofu_policy (engine_t engine,
                                            gpgme_key_t key,
                                            gpgme_tofu_policy_t policy);
gpgme_error_t _gpgme_engine_op_import (engine_t engine,
				       gpgme_data_t keydata,
                                       gpgme_key_t *keyarray,
                                       const char *keyids[],
                                       const char *import_filter,
                                       const char *import_options,
                                       const char *key_origin);
gpgme_error_t _gpgme_engine_op_keylist (engine_t engine,
					const char *pattern,
					int secret_only,
					gpgme_keylist_mode_t mode);
gpgme_error_t _gpgme_engine_op_keylist_ext (engine_t engine,
					    const char *pattern[],
					    int secret_only,
					    int reserved,
					    gpgme_keylist_mode_t mode);
gpgme_error_t _gpgme_engine_op_keylist_data (engine_t engine,
					     gpgme_keylist_mode_t mode,
					     gpgme_data_t data);
gpgme_error_t _gpgme_engine_op_sign (engine_t engine, gpgme_data_t in,
				     gpgme_data_t out, gpgme_sig_mode_t flags,
				     int use_armor, int use_textmode,
				     int include_certs,
				     gpgme_ctx_t ctx /* FIXME */);
gpgme_error_t _gpgme_engine_op_trustlist (engine_t engine,
					  const char *pattern);
gpgme_error_t _gpgme_engine_op_verify (engine_t engine,
                                       gpgme_verify_flags_t flags,
                                       gpgme_data_t sig,
				       gpgme_data_t signed_text,
				       gpgme_data_t plaintext,
                                       gpgme_ctx_t ctx);

gpgme_error_t _gpgme_engine_op_getauditlog (engine_t engine,
                                            gpgme_data_t output,
                                            unsigned int flags);
gpgme_error_t _gpgme_engine_op_assuan_transact
                (engine_t engine,
                 const char *command,
                 gpgme_assuan_data_cb_t data_cb,
                 void *data_cb_value,
                 gpgme_assuan_inquire_cb_t inq_cb,
                 void *inq_cb_value,
                 gpgme_assuan_status_cb_t status_cb,
                 void *status_cb_value);

gpgme_error_t _gpgme_engine_op_conf_load (engine_t engine,
					  gpgme_conf_comp_t *conf_p);
gpgme_error_t _gpgme_engine_op_conf_save (engine_t engine,
					  gpgme_conf_comp_t conf);
gpgme_error_t _gpgme_engine_op_conf_dir (engine_t engine,
					 const char *what,
					 char **result);

gpgme_error_t _gpgme_engine_op_query_swdb (engine_t engine,
                                           const char *name,
                                           const char *iversion,
                                           gpgme_query_swdb_result_t result);


void _gpgme_engine_set_io_cbs (engine_t engine,
			       gpgme_io_cbs_t io_cbs);
void _gpgme_engine_io_event (engine_t engine,
			     gpgme_event_io_t type, void *type_data);

gpgme_error_t _gpgme_engine_cancel (engine_t engine);

gpgme_error_t _gpgme_engine_cancel_op (engine_t engine);

gpgme_error_t _gpgme_engine_op_passwd (engine_t engine, gpgme_key_t key,
                                       unsigned int flags);

gpgme_error_t _gpgme_engine_set_pinentry_mode (engine_t engine,
                                               gpgme_pinentry_mode_t mode);

gpgme_error_t _gpgme_engine_op_spawn (engine_t engine,
                                      const char *file, const char *argv[],
                                      gpgme_data_t datain,
                                      gpgme_data_t dataout,
                                      gpgme_data_t dataerr,
                                      unsigned int flags);
gpgme_error_t _gpgme_engine_op_setexpire (engine_t engine,
                                          gpgme_key_t key,
                                          unsigned long expires,
                                          const char *subfprs,
                                          unsigned int reserved);


#endif /* ENGINE_H */

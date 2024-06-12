/* engine-backend.h - A crypto backend for the engine interface.
   Copyright (C) 2002, 2003, 2004, 2009 g10 Code GmbH

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
   License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ENGINE_BACKEND_H
#define ENGINE_BACKEND_H

#include "engine.h"

struct engine_ops
{
  /* Static functions.  */

  /* Return the default file name for the binary of this engine.  */
  const char *(*get_file_name) (void);

  /* Return the default home dir for the binary of this engine.  If
     this function pointer is not set, the standard default home dir
     of the engine is used. */
  const char *(*get_home_dir) (void);

  /* Returns a malloced string containing the version of the engine
     with the given binary file name (or the default if FILE_NAME is
     NULL.  */
  char *(*get_version) (const char *file_name);

  /* Returns a statically allocated string containing the required
     version.  */
  const char *(*get_req_version) (void);

  gpgme_error_t (*new) (void **r_engine,
			const char *file_name, const char *home_dir,
                        const char *version);

  /* Member functions.  */
  void (*release) (void *engine);
  gpgme_error_t (*reset) (void *engine);
  void (*set_status_cb) (void *engine, gpgme_status_cb_t cb, void *cb_value);
  void (*set_status_handler) (void *engine, engine_status_handler_t fnc,
			      void *fnc_value);
  gpgme_error_t (*set_command_handler) (void *engine,
					engine_command_handler_t fnc,
					void *fnc_value);
  gpgme_error_t (*set_colon_line_handler) (void *engine,
					   engine_colon_line_handler_t fnc,
					   void *fnc_value);
  gpgme_error_t (*set_locale) (void *engine, int category, const char *value);
  gpgme_error_t (*set_protocol) (void *engine, gpgme_protocol_t protocol);
  void (*set_engine_flags) (void *engine, gpgme_ctx_t ctx);
  gpgme_error_t (*decrypt) (void *engine,
                            gpgme_decrypt_flags_t flags,
                            gpgme_data_t ciph,
			    gpgme_data_t plain, int export_session_key,
                            const char *override_session_key,
                            int auto_key_retrieve);
  gpgme_error_t (*delete) (void *engine, gpgme_key_t key, unsigned int flags);
  gpgme_error_t (*edit) (void *engine, int type, gpgme_key_t key,
			 gpgme_data_t out, gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*encrypt) (void *engine, gpgme_key_t recp[],
                            const char *recpstring,
			    gpgme_encrypt_flags_t flags,
			    gpgme_data_t plain, gpgme_data_t ciph,
			    int use_armor);
  gpgme_error_t (*encrypt_sign) (void *engine, gpgme_key_t recp[],
                                 const char *recpstring,
				 gpgme_encrypt_flags_t flags,
				 gpgme_data_t plain, gpgme_data_t ciph,
				 int use_armor, gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*export) (void *engine, const char *pattern,
			   gpgme_export_mode_t mode, gpgme_data_t keydata,
			   int use_armor);
  gpgme_error_t (*export_ext) (void *engine, const char *pattern[],
			       gpgme_export_mode_t mode, gpgme_data_t keydata,
			       int use_armor);
  gpgme_error_t (*genkey) (void *engine,
                           const char *userid, const char *algo,
                           unsigned long reserved, unsigned long expires,
                           gpgme_key_t key, unsigned int flags,
                           gpgme_data_t help_data,
                           unsigned int extraflags,
			   gpgme_data_t pubkey, gpgme_data_t seckey);
  gpgme_error_t (*import) (void *engine, gpgme_data_t keydata,
                           gpgme_key_t *keyarray,
                           const char *keyids[],
                           const char *import_filter,
                           const char *import_options,
                           const char *key_origin);
  gpgme_error_t (*keylist) (void *engine, const char *pattern,
			    int secret_only, gpgme_keylist_mode_t mode);
  gpgme_error_t (*keylist_ext) (void *engine, const char *pattern[],
				int secret_only, int reserved,
				gpgme_keylist_mode_t mode);
  gpgme_error_t (*keylist_data) (void *engine, gpgme_keylist_mode_t mode,
				 gpgme_data_t data);
  gpgme_error_t (*keysign) (void *engine,
                            gpgme_key_t key, const char *userid,
                            unsigned long expires, unsigned int flags,
                            gpgme_ctx_t ctx);
  gpgme_error_t (*revsig) (void *engine,
                           gpgme_key_t key, gpgme_key_t signing_key,
                           const char *userid, unsigned int flags);
  gpgme_error_t (*tofu_policy) (void *engine,
                                gpgme_key_t key,
                                gpgme_tofu_policy_t policy);
  gpgme_error_t (*sign) (void *engine, gpgme_data_t in, gpgme_data_t out,
			 gpgme_sig_mode_t flags, int use_armor,
			 int use_textmode, int include_certs,
			 gpgme_ctx_t ctx /* FIXME */);
  gpgme_error_t (*verify) (void *engine, gpgme_verify_flags_t flags,
                           gpgme_data_t sig, gpgme_data_t signed_text,
                           gpgme_data_t plaintext, gpgme_ctx_t ctx);
  gpgme_error_t  (*getauditlog) (void *engine, gpgme_data_t output,
                                 unsigned int flags);
  gpgme_error_t (*setexpire) (void *engine, gpgme_key_t key,
                              unsigned long expires, const char *subfprs,
                              unsigned int reserved);
  gpgme_error_t  (*opassuan_transact) (void *engine,
                                       const char *command,
                                       gpgme_assuan_data_cb_t data_cb,
                                       void *data_cb_value,
                                       gpgme_assuan_inquire_cb_t inq_cb,
                                       void *inq_cb_value,
                                       gpgme_assuan_status_cb_t status_cb,
                                       void *status_cb_value);

  gpgme_error_t  (*conf_load) (void *engine, gpgme_conf_comp_t *conf_p);
  gpgme_error_t  (*conf_save) (void *engine, gpgme_conf_comp_t conf);
  gpgme_error_t  (*conf_dir) (void *engine, const char *what, char **result);

  gpgme_error_t  (*query_swdb) (void *engine,
                                const char *name, const char *iversion,
                                gpgme_query_swdb_result_t result);

  void (*set_io_cbs) (void *engine, gpgme_io_cbs_t io_cbs);
  void (*io_event) (void *engine, gpgme_event_io_t type, void *type_data);

  /* Cancel the whole engine session.  */
  gpgme_error_t (*cancel) (void *engine);

  /* Cancel only the current operation, not the whole session.  */
  gpgme_error_t (*cancel_op) (void *engine);

  /* Change the passphrase for KEY. */
  gpgme_error_t (*passwd) (void *engine, gpgme_key_t key, unsigned int flags);

  /* Set the pinentry mode.  */
  gpgme_error_t (*set_pinentry_mode) (void *engine, gpgme_pinentry_mode_t mode);

  /* The spawn command.  */
  gpgme_error_t (*opspawn) (void * engine,
                            const char *file, const char *argv[],
                            gpgme_data_t datain,
                            gpgme_data_t dataout,
                            gpgme_data_t dataerr, unsigned int flags);

};


extern struct engine_ops _gpgme_engine_ops_gpg;		/* OpenPGP.  */
extern struct engine_ops _gpgme_engine_ops_gpgsm;	/* CMS.  */
extern struct engine_ops _gpgme_engine_ops_gpgconf;	/* gpg-conf.  */
extern struct engine_ops _gpgme_engine_ops_assuan;	/* Low-level Assuan. */
extern struct engine_ops _gpgme_engine_ops_g13;         /* Crypto VFS. */
#ifdef ENABLE_UISERVER
extern struct engine_ops _gpgme_engine_ops_uiserver;
#endif
extern struct engine_ops _gpgme_engine_ops_spawn;       /* Spawn engine. */


/* Prototypes for extra functions in engine-gpgconf.c  */
gpgme_error_t _gpgme_conf_arg_new (gpgme_conf_arg_t *arg_p,
                                   gpgme_conf_type_t type, const void *value);
void _gpgme_conf_arg_release (gpgme_conf_arg_t arg, gpgme_conf_type_t type);
gpgme_error_t _gpgme_conf_opt_change (gpgme_conf_opt_t opt, int reset,
				      gpgme_conf_arg_t arg);
void _gpgme_conf_release (gpgme_conf_comp_t conf);
gpgme_error_t _gpgme_conf_load (void *engine, gpgme_conf_comp_t *conf_p);



#endif /* ENGINE_BACKEND_H */

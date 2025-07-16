/* ops.h - Internal operation support.
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2005 g10 Code GmbH

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

#ifndef OPS_H
#define OPS_H

#include "gpgme.h"
#include "context.h"


/* From gpgme.c.  */
gpgme_error_t _gpgme_cancel_with_err (gpgme_ctx_t ctx, gpg_error_t ctx_err,
				      gpg_error_t op_err);
/* Clear all notation data from the context.  */
void _gpgme_sig_notation_clear (gpgme_ctx_t ctx);

void _gpgme_release_result (gpgme_ctx_t ctx);


/* From wait.c.  */
gpgme_error_t _gpgme_wait_one (gpgme_ctx_t ctx);
gpgme_error_t _gpgme_wait_one_ext (gpgme_ctx_t ctx, gpgme_error_t *op_err);
gpgme_error_t _gpgme_wait_on_condition (gpgme_ctx_t ctx, volatile int *cond,
					gpgme_error_t *op_err);


/* From data.c.  */
gpgme_error_t _gpgme_data_inbound_handler (void *opaque, int fd);
gpgme_error_t _gpgme_data_outbound_handler (void *opaque, int fd);


/* From op-support.c.  */

/* Find or create the op data object of type TYPE.  */
gpgme_error_t _gpgme_op_data_lookup (gpgme_ctx_t ctx, ctx_op_data_id_t type,
				     void **hook, int size,
				     void (*cleanup) (void *));

/* Prepare a new operation on CTX.  */
gpgme_error_t _gpgme_op_reset (gpgme_ctx_t ctx, int synchronous);

/* Parse the KEY_CONSIDERED status line.  */
gpgme_error_t _gpgme_parse_key_considered (const char *args,
                                           char **r_fpr, unsigned int *r_flags);

/* Parse the INV_RECP status line in ARGS and return the result in
   KEY.  */
gpgme_error_t _gpgme_parse_inv_recp (char *args, int for_signing,
                                     const char *kc_fpr, unsigned int kc_flags,
                                     gpgme_invalid_key_t *key);

/* Parse the PLAINTEXT status line in ARGS and return the result in
   FILENAMEP and R_MIME.  */
gpgme_error_t _gpgme_parse_plaintext (char *args, char **filenamep,int *r_mime);

/* Parse a FAILURE status line and return the error code.  ARGS is
   modified to contain the location part.  */
gpgme_error_t _gpgme_parse_failure (char *args);



/* From verify.c.  */
gpgme_error_t _gpgme_op_verify_init_result (gpgme_ctx_t ctx);
gpgme_error_t _gpgme_verify_status_handler (void *priv,
					    gpgme_status_code_t code,
					    char *args);


/* From decrypt.c.  */
gpgme_error_t _gpgme_op_decrypt_init_result (gpgme_ctx_t ctx,
                                             gpgme_data_t plaintext,
                                             gpgme_decrypt_flags_t flags);
gpgme_error_t _gpgme_decrypt_status_handler (void *priv,
					     gpgme_status_code_t code,
					     char *args);
gpgme_error_t _gpgme_decrypt_start (gpgme_ctx_t ctx, int synchronous,
                                    gpgme_decrypt_flags_t flags,
                                    gpgme_data_t cipher, gpgme_data_t plain);


/* From signers.c.  */
void _gpgme_signers_clear (gpgme_ctx_t ctx);

/* From sign.c.  */

/* Create an initial op data object for signing.  Needs to be called
   once before calling _gpgme_sign_status_handler.  */
gpgme_error_t _gpgme_op_sign_init_result (gpgme_ctx_t ctx,
                                          int success_required);

/* Process a status line for signing operations.  */
gpgme_error_t _gpgme_sign_status_handler (void *priv,
					  gpgme_status_code_t code,
					  char *args);


/* From encrypt.c.  */

/* Create an initial op data object for encrypt.  Needs to be called
   once before calling _gpgme_encrypt_status_handler.  */
gpgme_error_t _gpgme_op_encrypt_init_result (gpgme_ctx_t ctx,
                                             int success_required);

/* Process a status line for encryption operations.  */
gpgme_error_t _gpgme_encrypt_status_handler (void *priv,
					     gpgme_status_code_t code,
					     char *args);


/* From passphrase.c.  */
gpgme_error_t _gpgme_passphrase_status_handler (void *priv,
						gpgme_status_code_t code,
						char *args);
gpgme_error_t _gpgme_passphrase_command_handler (void *opaque,
						 gpgme_status_code_t code,
						 const char *key, int fd,
						 int *processed);


/* From progress.c.  */
gpgme_error_t _gpgme_progress_status_handler (void *priv,
					      gpgme_status_code_t code,
					      char *args);


/* From key.c.  */
gpgme_error_t _gpgme_key_new (gpgme_key_t *r_key);
gpgme_error_t _gpgme_key_add_subkey (gpgme_key_t key,
				     gpgme_subkey_t *r_subkey);
gpgme_error_t _gpgme_key_append_name (gpgme_key_t key,
                                      const char *src, int convert);
gpgme_key_sig_t _gpgme_key_add_uid_sig (gpgme_key_t key, char *src);
gpgme_error_t _gpgme_key_add_rev_key (gpgme_key_t key, const char *src);



/* From keylist.c.  */
void _gpgme_op_keylist_event_cb (void *data, gpgme_event_io_t type,
				 void *type_data);


/* From version.c.  */

/* Return true if MY_VERSION is at least REQ_VERSION, and false
   otherwise.  */
int _gpgme_compare_versions (const char *my_version,
			     const char *req_version);
char *_gpgme_get_program_version (const char *const path);


/* From sig-notation.c.  */

/* Create a new, empty signature notation data object.  */
gpgme_error_t _gpgme_sig_notation_create (gpgme_sig_notation_t *notationp,
					  const char *name, int name_len,
					  const char *value, int value_len,
					  gpgme_sig_notation_flags_t flags);

/* Free the signature notation object and all associated resources.
   The object must already be removed from any linked list as the next
   pointer is ignored.  */
void _gpgme_sig_notation_free (gpgme_sig_notation_t notation);

/* Parse a notation or policy URL subpacket.  If the packet type is
   not known, return no error but NULL in NOTATION.  */
gpgme_error_t _gpgme_parse_notation (gpgme_sig_notation_t *notationp,
				     int type, int pkflags, int len,
				     char *data);


/* From import.c.  */

/* Create an initial op data object for import.  Needs to be called
   once before calling _gpgme_import_status_handler.  */
gpgme_error_t _gpgme_op_import_init_result (gpgme_ctx_t ctx);

/* Process a status line for import operations.  */
gpgme_error_t _gpgme_import_status_handler (void *priv,
                                            gpgme_status_code_t code,
                                            char *args);

#endif /* OPS_H */

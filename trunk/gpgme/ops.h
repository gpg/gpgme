/* ops.h - internal operations stuff 
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

#ifndef OPS_H
#define OPS_H

#include "gpgme.h"
#include "context.h"

/*-- gpgme.c --*/
void _gpgme_release_result (GpgmeCtx ctx);
void _gpgme_set_op_info (GpgmeCtx c, GpgmeData info);

/*-- wait.c --*/
GpgmeError _gpgme_wait_one (GpgmeCtx ctx);
GpgmeError _gpgme_wait_on_condition (GpgmeCtx ctx, volatile int *cond);

/*-- recipient.c --*/
int _gpgme_recipients_all_valid ( const GpgmeRecipients rset );


/*-- data.c and conversion.c --*/
char *        _gpgme_data_release_and_return_string ( GpgmeData dh );
char *        _gpgme_data_get_as_string ( GpgmeData dh );
GpgmeError    _gpgme_data_append ( GpgmeData dh,
                                   const char *buffer, size_t length );
GpgmeError    _gpgme_data_append_string ( GpgmeData dh, const char *s );
GpgmeError    _gpgme_data_append_string_for_xml ( GpgmeData dh,
                                                  const char *s);
GpgmeError    _gpgme_data_append_for_xml ( GpgmeData dh,
                                           const char *buffer,
                                           size_t len );
GpgmeError    _gpgme_data_append_percentstring_for_xml ( GpgmeData dh,
                                                         const char *string );

GpgmeError _gpgme_data_inbound_handler (void *opaque, int fd);
GpgmeError _gpgme_data_outbound_handler (void *opaque, int fd);

/*-- key.c --*/
GpgmeError _gpgme_key_new ( GpgmeKey *r_key );
GpgmeError _gpgme_key_new_secret ( GpgmeKey *r_key );

/*-- op-support.c --*/
GpgmeError _gpgme_op_data_lookup (GpgmeCtx ctx, ctx_op_data_type type,
				  void **hook, int size,
				  void (*cleanup) (void *));
GpgmeError _gpgme_op_reset (GpgmeCtx ctx, int synchronous);

/*-- verify.c --*/
GpgmeError _gpgme_verify_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
					 char *args);

/*-- decrypt.c --*/
GpgmeError _gpgme_decrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
					  char *args);
GpgmeError _gpgme_decrypt_start (GpgmeCtx ctx, int synchronous,
				 GpgmeData ciph, GpgmeData plain,
				 void *status_handler);

/*-- sign.c --*/
GpgmeError _gpgme_sign_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				       char *args);

/*-- encrypt.c --*/
GpgmeError _gpgme_encrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
					  char *args);

/*-- passphrase.c --*/
GpgmeError _gpgme_passphrase_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
					     char *args);
GpgmeError _gpgme_passphrase_command_handler (void *opaque,
					      GpgmeStatusCode code,
					      const char *key, const char **result);
GpgmeError _gpgme_passphrase_start (GpgmeCtx ctx);

/*-- progress.c --*/
GpgmeError _gpgme_progress_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
					   char *args);


/* From key-cache.c.  */

/* Acquire a reference to KEY and add it to the key cache.  */
void _gpgme_key_cache_add (GpgmeKey key);

/* Look up a key with fingerprint FPR in the key cache.  If such a key
   is found, a reference is acquired for it and it is returned.
   Otherwise, NULL is returned.  */
GpgmeKey _gpgme_key_cache_get (const char *fpr);

/*-- keylist.c --*/
void _gpgme_op_keylist_event_cb (void *data, GpgmeEventIO type, void *type_data);

/*-- trustlist.c --*/
void _gpgme_op_trustlist_event_cb (void *data, GpgmeEventIO type, void *type_data);

/*-- version.c --*/
const char *_gpgme_compare_versions (const char *my_version,
				     const char *req_version);
char *_gpgme_get_program_version (const char *const path);


#endif /* OPS_H */

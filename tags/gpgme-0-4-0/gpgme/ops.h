/* ops.h - internal operations stuff 
   Copyright (C) 2000 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002 g10 Code GmbH
 
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

#include "types.h"

/* Support macros.  */

#define test_and_allocate_result(ctx,field) \
  do \
    { \
      if (!ctx->result.field) \
        { \
          ctx->result.field = calloc (1, sizeof *ctx->result.field); \
          if (!ctx->result.field) \
            { \
              ctx->error = mk_error (Out_Of_Core); \
              return; \
            } \
        } \
    } \
  while (0)

/*-- gpgme.c --*/
void _gpgme_release_result ( GpgmeCtx c );
void _gpgme_set_op_info (GpgmeCtx c, GpgmeData info);

void _gpgme_op_event_cb (void *data, GpgmeEventIO type, void *type_data);
void _gpgme_op_event_cb_user (void *data, GpgmeEventIO type, void *type_data);

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

GpgmeError    _gpgme_data_unread (GpgmeData dh,
                                  const char *buffer, size_t length );

void _gpgme_data_inbound_handler (void *opaque, int fd);
void _gpgme_data_outbound_handler (void *opaque, int fd);

/*-- key.c --*/
GpgmeError _gpgme_key_new ( GpgmeKey *r_key );
GpgmeError _gpgme_key_new_secret ( GpgmeKey *r_key );

/*-- op-support.c --*/
GpgmeError _gpgme_op_reset (GpgmeCtx ctx, int synchronous);

/*-- verify.c --*/
void _gpgme_release_verify_result (VerifyResult result);
GpgmeSigStat _gpgme_intersect_stati (VerifyResult result);
void _gpgme_verify_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				   char *args);

/*-- decrypt.c --*/
void _gpgme_release_decrypt_result (DecryptResult result);
void _gpgme_decrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				    char *args);
GpgmeError _gpgme_decrypt_start (GpgmeCtx ctx, int synchronous,
				 GpgmeData ciph, GpgmeData plain,
				 void *status_handler);
GpgmeError _gpgme_decrypt_result (GpgmeCtx ctx);

/*-- sign.c --*/
void _gpgme_release_sign_result ( SignResult res );
void _gpgme_sign_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				 char *args);

/*-- encrypt.c --*/
void _gpgme_release_encrypt_result ( EncryptResult res );
void _gpgme_encrypt_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				    char *args);

/*-- passphrase.c --*/
void _gpgme_release_passphrase_result (PassphraseResult result);
void _gpgme_passphrase_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				       char *args);
const char * _gpgme_passphrase_command_handler (void *opaque,
						GpgmeStatusCode code,
						const char *key);
GpgmeError _gpgme_passphrase_start (GpgmeCtx ctx);

/*-- progress.c --*/
void _gpgme_progress_status_handler (GpgmeCtx ctx, GpgmeStatusCode code,
				     char *args);

/*-- import.c --*/
void _gpgme_release_import_result (ImportResult res);

/*-- delete.c --*/
void _gpgme_release_delete_result (DeleteResult res);

/*-- genkey.c --*/
void _gpgme_release_genkey_result (GenKeyResult res);

/*-- keylist.c --*/
void _gpgme_release_keylist_result (KeylistResult res);
void _gpgme_op_keylist_event_cb (void *data, GpgmeEventIO type, void *type_data);

/*-- trustlist.c --*/
void _gpgme_op_trustlist_event_cb (void *data, GpgmeEventIO type, void *type_data);

/*-- edit.c --*/
void _gpgme_release_edit_result (EditResult res);

/*-- version.c --*/
const char *_gpgme_compare_versions (const char *my_version,
				     const char *req_version);
char *_gpgme_get_program_version (const char *const path);


#endif /* OPS_H */

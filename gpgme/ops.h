/* ops.h - internal operations stuff 
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

#ifndef OPS_H
#define OPS_H

#include "types.h"

/*-- gpgme.c --*/
void _gpgme_release_result ( GpgmeCtx c );
void _gpgme_set_op_info (GpgmeCtx c, GpgmeData info);

/*-- wait.c --*/
GpgmeCtx _gpgme_wait_on_condition ( GpgmeCtx c,
                                    int hang, volatile int *cond );
void _gpgme_freeze_fd ( int fd );
void _gpgme_thaw_fd ( int fd );


/*-- recipient.c --*/
void _gpgme_append_gpg_args_from_recipients (
    const GpgmeRecipients rset,
    GpgObject gpg );
int _gpgme_recipients_all_valid ( const GpgmeRecipients rset );


/*-- data.c --*/
char *        _gpgme_data_release_and_return_string ( GpgmeData dh );
GpgmeDataMode _gpgme_data_get_mode ( GpgmeData dh );
void          _gpgme_data_set_mode ( GpgmeData dh, GpgmeDataMode mode );
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


/*-- key.c --*/
GpgmeError _gpgme_key_new ( GpgmeKey *r_key );
GpgmeError _gpgme_key_new_secret ( GpgmeKey *r_key );


/*-- verify.c --*/
void _gpgme_release_verify_result ( VerifyResult res );

/*-- decrypt.c --*/
void _gpgme_release_decrypt_result ( DecryptResult res );

/*-- sign.c --*/
void _gpgme_release_sign_result ( SignResult res );

/*-- encrypt.c --*/
void _gpgme_release_encrypt_result ( EncryptResult res );


#endif /* OPS_H */






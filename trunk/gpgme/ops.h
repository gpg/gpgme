/* ops.h - internal operations stuff 
 *	Copyright (C) 2000 Werner Koch (dd9jn)
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

/*-- wait.c --*/
GpgmeCtx _gpgme_wait_on_condition ( GpgmeCtx c,
                                    int hang, volatile int *cond );


/*-- recipient.c --*/
void _gpgme_append_gpg_args_from_recipients (
    const GpgmeRecipientSet rset,
    GpgObject gpg );


/*-- data.c --*/
GpgmeDataMode _gpgme_query_data_mode ( GpgmeData dh );
void          _gpgme_set_data_mode ( GpgmeData dh, GpgmeDataMode mode );
GpgmeError    _gpgme_append_data ( GpgmeData dh,
                                   const char *buffer, size_t length );

/*-- key.c --*/
GpgmeError _gpgme_key_new( GpgmeKey *r_key );
void       _gpgme_key_release ( GpgmeKey key );


/*-- verify.c --*/
void _gpgme_release_verify_result ( VerifyResult res );


#endif /* OPS_H */






/* rungpg.h -  gpg calling functions
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

#ifndef RUNGPG_H
#define RUNGPG_H

#include "types.h"


typedef enum  {
    STATUS_EOF ,
    /* mkstatus starts here */
    STATUS_ENTER	      , 
    STATUS_LEAVE	      ,
    STATUS_ABORT	      ,
    STATUS_GOODSIG	      ,
    STATUS_BADSIG	      ,
    STATUS_ERRSIG	      ,
    STATUS_BADARMOR           ,
    STATUS_RSA_OR_IDEA        ,
    STATUS_SIGEXPIRED         ,
    STATUS_KEYREVOKED         ,
    STATUS_TRUST_UNDEFINED    ,
    STATUS_TRUST_NEVER        ,
    STATUS_TRUST_MARGINAL     ,
    STATUS_TRUST_FULLY        ,
    STATUS_TRUST_ULTIMATE     ,
    STATUS_SHM_INFO           ,
    STATUS_SHM_GET	      ,
    STATUS_SHM_GET_BOOL       ,
    STATUS_SHM_GET_HIDDEN     ,
    STATUS_NEED_PASSPHRASE    ,
    STATUS_USERID_HINT        ,
    STATUS_VALIDSIG           ,
    STATUS_SIG_ID	      ,
    STATUS_ENC_TO	      ,
    STATUS_NODATA	      ,
    STATUS_BAD_PASSPHRASE     ,
    STATUS_NO_PUBKEY          ,
    STATUS_NO_SECKEY          ,
    STATUS_NEED_PASSPHRASE_SYM,
    STATUS_DECRYPTION_FAILED  ,
    STATUS_DECRYPTION_OKAY    ,
    STATUS_MISSING_PASSPHRASE ,
    STATUS_GOOD_PASSPHRASE    ,
    STATUS_GOODMDC	      ,
    STATUS_BADMDC	      ,
    STATUS_ERRMDC	      ,
    STATUS_IMPORTED 	      ,
    STATUS_IMPORT_RES	      ,
    STATUS_FILE_START	      ,
    STATUS_FILE_DONE	      ,
    STATUS_FILE_ERROR	      ,
    STATUS_BEGIN_DECRYPTION   ,
    STATUS_END_DECRYPTION     ,
    STATUS_BEGIN_ENCRYPTION   ,
    STATUS_END_ENCRYPTION     ,
    STATUS_DELETE_PROBLEM     ,
    STATUS_GET_BOOL 	      ,
    STATUS_GET_LINE 	      ,
    STATUS_GET_HIDDEN	      ,
    STATUS_GOT_IT	      ,
    STATUS_PROGRESS 	      ,
    STATUS_SIG_CREATED	      ,
    STATUS_SESSION_KEY        ,
    STATUS_NOTATION_NAME      ,
    STATUS_NOTATION_DATA      ,
    STATUS_POLICY_URL         ,
    STATUS_BEGIN_STREAM       ,
    STATUS_END_STREAM
} GpgStatusCode;

typedef void (*GpgStatusHandler)( GpgmeCtx, GpgStatusCode code, char *args ); 
typedef void (*GpgColonLineHandler)( GpgmeCtx, char *line ); 
typedef const char *(*GpgCommandHandler)(void*, GpgStatusCode code,
                                         const char *keyword);


GpgmeError _gpgme_gpg_new ( GpgObject *r_gpg );
void       _gpgme_gpg_release ( GpgObject gpg );
void       _gpgme_gpg_housecleaning (void);
void       _gpgme_gpg_enable_pipemode ( GpgObject gpg );
GpgmeError _gpgme_gpg_add_arg ( GpgObject gpg, const char *arg );
GpgmeError _gpgme_gpg_add_data ( GpgObject gpg, GpgmeData data, int dup_to );
GpgmeError _gpgme_gpg_add_pm_data ( GpgObject gpg, GpgmeData data, int what );
void       _gpgme_gpg_set_status_handler ( GpgObject gpg,
                                           GpgStatusHandler fnc,
                                           void *fnc_value );
GpgmeError _gpgme_gpg_set_colon_line_handler ( GpgObject gpg,
                                               GpgColonLineHandler fnc,
                                               void *fnc_value );
GpgmeError _gpgme_gpg_set_simple_line_handler ( GpgObject gpg,
                                                GpgColonLineHandler fnc,
                                                void *fnc_value );
GpgmeError _gpgme_gpg_set_command_handler ( GpgObject gpg,
                                            GpgCommandHandler fnc,
                                            void *fnc_value );

GpgmeError _gpgme_gpg_spawn ( GpgObject gpg, void *opaque );



#endif /* RUNGPG_H */







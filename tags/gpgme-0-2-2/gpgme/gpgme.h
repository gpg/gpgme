/* gpgme.h -  GnuPG Made Easy
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

#ifndef GPGME_H
#define GPGME_H

#include <stdio.h> /* for FILE * */
#ifdef _MSC_VER
  typedef long off_t;
#else
# include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" { 
#if 0 /* just to make Emacs auto-indent happy */
}
#endif
#endif


/*
 * The version of this header should match the one of the library
 * It should not be used by a program because gpgme_check_version(NULL)
 * does return the same version.  The purpose of this macro is to
 * let autoconf (using the AM_PATH_GPGME macro) check that this
 * header matches the installed library.
 * Warning: Do not edit the next line.  configure will do that for you! */
#define GPGME_VERSION "0.2.2"



struct gpgme_context_s;
typedef struct gpgme_context_s *GpgmeCtx;

struct gpgme_data_s;
typedef struct gpgme_data_s *GpgmeData;

struct gpgme_recipients_s;
typedef struct gpgme_recipients_s *GpgmeRecipients;

struct gpgme_key_s;
typedef struct gpgme_key_s *GpgmeKey;

struct gpgme_trust_item_s;
typedef struct gpgme_trust_item_s *GpgmeTrustItem;


typedef enum {
    GPGME_EOF = -1,
    GPGME_No_Error = 0,
    GPGME_General_Error = 1,
    GPGME_Out_Of_Core = 2,
    GPGME_Invalid_Value = 3,
    GPGME_Busy = 4,
    GPGME_No_Request = 5,
    GPGME_Exec_Error = 6,
    GPGME_Too_Many_Procs = 7,
    GPGME_Pipe_Error = 8,
    GPGME_No_Recipients = 9,
    GPGME_No_Data = 10,
    GPGME_Conflict = 11,
    GPGME_Not_Implemented = 12,
    GPGME_Read_Error = 13,
    GPGME_Write_Error = 14,
    GPGME_Invalid_Type = 15,
    GPGME_Invalid_Mode = 16,
    GPGME_File_Error = 17,  /* errno is set in this case */
    GPGME_Decryption_Failed = 18,
    GPGME_No_Passphrase = 19,
    GPGME_Canceled = 20,
    GPGME_Invalid_Key = 21,
    GPGME_Invalid_Engine = 22,
} GpgmeError;

typedef enum {
    GPGME_DATA_TYPE_NONE = 0,
    GPGME_DATA_TYPE_MEM  = 1,
    GPGME_DATA_TYPE_FD   = 2,
    GPGME_DATA_TYPE_FILE = 3,
    GPGME_DATA_TYPE_CB   = 4
} GpgmeDataType;

typedef enum {
    GPGME_SIG_STAT_NONE = 0,
    GPGME_SIG_STAT_GOOD = 1,
    GPGME_SIG_STAT_BAD  = 2,
    GPGME_SIG_STAT_NOKEY = 3,
    GPGME_SIG_STAT_NOSIG = 4,
    GPGME_SIG_STAT_ERROR = 5,
    GPGME_SIG_STAT_DIFF  = 6
} GpgmeSigStat;

typedef enum {
    GPGME_SIG_MODE_NORMAL = 0,
    GPGME_SIG_MODE_DETACH = 1,
    GPGME_SIG_MODE_CLEAR = 2
} GpgmeSigMode;

typedef enum {
    GPGME_ATTR_KEYID   = 1,
    GPGME_ATTR_FPR     = 2,
    GPGME_ATTR_ALGO    = 3,
    GPGME_ATTR_LEN     = 4,
    GPGME_ATTR_CREATED = 5,
    GPGME_ATTR_EXPIRE  = 6,
    GPGME_ATTR_OTRUST  = 7,
    GPGME_ATTR_USERID  = 8,
    GPGME_ATTR_NAME    = 9,
    GPGME_ATTR_EMAIL   = 10,
    GPGME_ATTR_COMMENT = 11,
    GPGME_ATTR_VALIDITY= 12,
    GPGME_ATTR_LEVEL   = 13,
    GPGME_ATTR_TYPE    = 14,
    GPGME_ATTR_IS_SECRET= 15,
    GPGME_ATTR_KEY_REVOKED = 16,
    GPGME_ATTR_KEY_INVALID = 17,
    GPGME_ATTR_UID_REVOKED = 18,
    GPGME_ATTR_UID_INVALID = 19,
    GPGME_ATTR_KEY_CAPS    = 20,
    GPGME_ATTR_CAN_ENCRYPT = 21,
    GPGME_ATTR_CAN_SIGN    = 22,
    GPGME_ATTR_CAN_CERTIFY = 23,
    GPGME_ATTR_KEY_EXPIRED = 24,
    GPGME_ATTR_KEY_DISABLED= 25
} GpgmeAttr;

typedef enum {
    GPGME_VALIDITY_UNKNOWN = 0,
    GPGME_VALIDITY_UNDEFINED = 1,
    GPGME_VALIDITY_NEVER = 2,
    GPGME_VALIDITY_MARGINAL = 3,
    GPGME_VALIDITY_FULL = 4,
    GPGME_VALIDITY_ULTIMATE = 5
} GpgmeValidity;


typedef const char *(*GpgmePassphraseCb)(void*,
                                         const char *desc, void *r_hd);
typedef void (*GpgmeProgressCb)(void *opaque,
                                const char *what, 
                                int type, int current, int total );


/* Context management */
GpgmeError gpgme_new (GpgmeCtx *r_ctx);
void       gpgme_release (GpgmeCtx c);
void       gpgme_cancel (GpgmeCtx c);
GpgmeCtx   gpgme_wait (GpgmeCtx c, int hang);

char *gpgme_get_notation (GpgmeCtx c);
void gpgme_set_armor (GpgmeCtx c, int yes);
void gpgme_set_textmode (GpgmeCtx c, int yes);
void gpgme_set_keylist_mode ( GpgmeCtx c, int mode );
void gpgme_set_passphrase_cb (GpgmeCtx c,
                              GpgmePassphraseCb cb, void *cb_value);
void gpgme_set_progress_cb (GpgmeCtx c, GpgmeProgressCb cb, void *cb_value);

void       gpgme_signers_clear (GpgmeCtx c);
GpgmeError gpgme_signers_add (GpgmeCtx c, const GpgmeKey key);
GpgmeKey   gpgme_signers_enum (const GpgmeCtx c, int seq);

const char *gpgme_get_sig_status (GpgmeCtx c, int idx,
                                  GpgmeSigStat *r_stat, time_t *r_created );
GpgmeError gpgme_get_sig_key (GpgmeCtx c, int idx, GpgmeKey *r_key);




/* Functions to handle recipients */
GpgmeError   gpgme_recipients_new (GpgmeRecipients *r_rset);
void         gpgme_recipients_release ( GpgmeRecipients rset);
GpgmeError   gpgme_recipients_add_name (GpgmeRecipients rset,
                                        const char *name);
GpgmeError   gpgme_recipients_add_name_with_validity (GpgmeRecipients rset,
                                                      const char *name,
                                                      GpgmeValidity val );
unsigned int gpgme_recipients_count ( const GpgmeRecipients rset );
GpgmeError gpgme_recipients_enum_open (const GpgmeRecipients rset,void **ctx);
const char *gpgme_recipients_enum_read (const GpgmeRecipients rset,void **ctx);
GpgmeError gpgme_recipients_enum_close (const GpgmeRecipients rset,void **ctx);


/* Functions to handle data sources */
GpgmeError    gpgme_data_new ( GpgmeData *r_dh );
GpgmeError    gpgme_data_new_from_mem ( GpgmeData *r_dh,
                                        const char *buffer, size_t size,
                                        int copy );
GpgmeError    gpgme_data_new_with_read_cb ( GpgmeData *r_dh,
                              int (*read_cb)(void*,char *,size_t,size_t*),
                              void *read_cb_value );

GpgmeError    gpgme_data_new_from_file ( GpgmeData *r_dh,
                                         const char *fname,
                                         int copy );
GpgmeError    gpgme_data_new_from_filepart ( GpgmeData *r_dh,
                                             const char *fname, FILE *fp,
                                             off_t offset, off_t length );
void          gpgme_data_release ( GpgmeData dh );
char *        gpgme_data_release_and_get_mem ( GpgmeData dh, size_t *r_len );
GpgmeDataType gpgme_data_get_type ( GpgmeData dh );
GpgmeError    gpgme_data_rewind ( GpgmeData dh );
GpgmeError    gpgme_data_read ( GpgmeData dh,
                                char *buffer, size_t length, size_t *nread );
GpgmeError    gpgme_data_write ( GpgmeData dh,
                                 const char *buffer, size_t length );


/* Key and trust functions */
void gpgme_key_ref (GpgmeKey key);
void gpgme_key_unref (GpgmeKey key);
void gpgme_key_release ( GpgmeKey key );
char *gpgme_key_get_as_xml ( GpgmeKey key );
const char  *gpgme_key_get_string_attr ( GpgmeKey key, GpgmeAttr what,
                                         const void *reserved, int idx );
unsigned long gpgme_key_get_ulong_attr ( GpgmeKey key, GpgmeAttr what,
                                         const void *reserved, int idx );

void gpgme_trust_item_release ( GpgmeTrustItem item );
const char *gpgme_trust_item_get_string_attr ( GpgmeTrustItem item,
                                               GpgmeAttr what,
                                               const void *reserved, int idx );
int gpgme_trust_item_get_int_attr ( GpgmeTrustItem item, GpgmeAttr what,
                                    const void *reserved, int idx );




/* Basic GnuPG functions */
GpgmeError gpgme_op_encrypt_start ( GpgmeCtx c,
                                    GpgmeRecipients recp,
                                    GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_decrypt_start ( GpgmeCtx c, 
                                    GpgmeData ciph, GpgmeData plain );
GpgmeError gpgme_op_sign_start ( GpgmeCtx c,
                                 GpgmeData in, GpgmeData out,
                                 GpgmeSigMode mode );
GpgmeError gpgme_op_verify_start ( GpgmeCtx c,
                                   GpgmeData sig, GpgmeData text );
GpgmeError gpgme_op_import_start ( GpgmeCtx c, GpgmeData keydata );
GpgmeError gpgme_op_export_start ( GpgmeCtx c, GpgmeRecipients recp,
                                   GpgmeData keydata );
GpgmeError gpgme_op_genkey_start ( GpgmeCtx c, const char *parms,
                                   GpgmeData pubkey, GpgmeData seckey );
GpgmeError gpgme_op_delete_start ( GpgmeCtx c, const GpgmeKey key,
                                   int allow_secret );




/* Key management functions */
GpgmeError gpgme_op_keylist_start ( GpgmeCtx c,
                                    const char *pattern, int secret_only );
GpgmeError gpgme_op_keylist_next ( GpgmeCtx c, GpgmeKey *r_key );
GpgmeError gpgme_op_trustlist_start ( GpgmeCtx c,
                                      const char *pattern, int max_level );
GpgmeError gpgme_op_trustlist_next ( GpgmeCtx c, GpgmeTrustItem *r_item );



/* Convenience functions for normal usage */
GpgmeError gpgme_op_encrypt ( GpgmeCtx c, GpgmeRecipients recp,
                              GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_decrypt ( GpgmeCtx c, 
                              GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_sign ( GpgmeCtx c, GpgmeData in, GpgmeData out,
                           GpgmeSigMode mode);
GpgmeError gpgme_op_verify ( GpgmeCtx c, GpgmeData sig, GpgmeData text,
                             GpgmeSigStat *r_status );
GpgmeError gpgme_op_import ( GpgmeCtx c, GpgmeData keydata );
GpgmeError gpgme_op_export ( GpgmeCtx c, GpgmeRecipients recp,
                             GpgmeData keydata );
GpgmeError gpgme_op_genkey ( GpgmeCtx c, const char *parms,
                             GpgmeData pubkey, GpgmeData seckey );
GpgmeError gpgme_op_delete ( GpgmeCtx c, const GpgmeKey key, int allow_secret);


/* miscellaneous functions */
const char *gpgme_check_version (const char *req_version);
GpgmeError  gpgme_check_engine (void);
const char *gpgme_get_engine_info (void);
const char *gpgme_strerror (GpgmeError err);
void        gpgme_register_idle (void (*fnc)(void));


#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */








/* gpgme.h -  GnuPG Made Easy
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

#ifndef GPGME_H
#define GPGME_H
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
#define GPGME_VERSION "0.1.0"



struct gpgme_context_s;
typedef struct gpgme_context_s *GpgmeCtx;

struct gpgme_data_s;
typedef struct gpgme_data_s *GpgmeData;

struct gpgme_recipients_s;
typedef struct gpgme_recipients_s *GpgmeRecipients;

struct gpgme_key_s;
typedef struct gpgme_key_s *GpgmeKey;


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
} GpgmeError;

typedef enum {
    GPGME_DATA_TYPE_NONE = 0,
    GPGME_DATA_TYPE_MEM  = 1,
    GPGME_DATA_TYPE_FD   = 2,
    GPGME_DATA_TYPE_FILE = 3
} GpgmeDataType;

typedef enum {
    GPGME_SIG_STAT_NONE = 0,
    GPGME_SIG_STAT_GOOD = 1,
    GPGME_SIG_STAT_BAD  = 2,
    GPGME_SIG_STAT_NOKEY = 3,
    GPGME_SIG_STAT_NOSIG = 4,
    GPGME_SIG_STAT_ERROR = 5
} GpgmeSigStat;

/*typedef GpgmeData (*GpgmePassphraseCb)( void *opaque, const char *desc );*/


/* Context management */
GpgmeError gpgme_new (GpgmeCtx *r_ctx);
void       gpgme_release ( GpgmeCtx c );
GpgmeCtx   gpgme_wait ( GpgmeCtx c, int hang );

char *gpgme_get_notation ( GpgmeCtx c );
void gpgme_set_armor ( GpgmeCtx c, int yes );
void gpgme_set_textmode ( GpgmeCtx c, int yes );
/*void gpgme_set_passphrase_cb ( GpgmeCtx c,
  GpgmePassphraseCb fnc, void *fncval );*/


/* Functions to handle recipients */
GpgmeError   gpgme_recipients_new (GpgmeRecipients *r_rset);
void         gpgme_recipients_release ( GpgmeRecipients rset);
GpgmeError   gpgme_recipients_add_name (GpgmeRecipients rset,
                                        const char *name);
unsigned int gpgme_recipients_count ( const GpgmeRecipients rset );

/* Functions to handle data sources */
GpgmeError    gpgme_data_new ( GpgmeData *r_dh );
GpgmeError    gpgme_data_new_from_mem ( GpgmeData *r_dh,
                                        const char *buffer, size_t size,
                                        int copy );
GpgmeError    gpgme_data_new_from_file ( GpgmeData *r_dh,
                                         const char *fname,
                                         int copy );
void          gpgme_data_release ( GpgmeData dh );
char *        gpgme_data_release_and_get_mem ( GpgmeData dh, size_t *r_len );
GpgmeDataType gpgme_data_get_type ( GpgmeData dh );
GpgmeError    gpgme_data_rewind ( GpgmeData dh );
GpgmeError    gpgme_data_read ( GpgmeData dh,
                                char *buffer, size_t length, size_t *nread );

/* Key functions */
char *gpgme_key_get_as_xml ( GpgmeKey key );


/* Basic GnuPG functions */
GpgmeError gpgme_op_encrypt_start ( GpgmeCtx c,
                                    GpgmeRecipients recp,
                                    GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_decrypt_start ( GpgmeCtx c,
                                    GpgmeData ciph, GpgmeData plain );
GpgmeError gpgme_op_sign_start ( GpgmeCtx c, GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_verify_start ( GpgmeCtx c,
                                   GpgmeData sig, GpgmeData text );


/* Key management functions */
GpgmeError gpgme_op_keylist_start ( GpgmeCtx c,
                                    const char *pattern, int secret_only );
GpgmeError gpgme_op_keylist_next ( GpgmeCtx c, GpgmeKey *r_key );


/* Convenience functions for normal usage */
GpgmeError gpgme_op_encrypt ( GpgmeCtx c, GpgmeRecipients recp,
                              GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_decrypt ( GpgmeCtx c, GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_sign ( GpgmeCtx c, GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_verify ( GpgmeCtx c, GpgmeData sig, GpgmeData text,
                             GpgmeSigStat *r_status );


/* miscellaneous functions */
const char *gpgme_check_version ( const char *req_version );
const char *gpgme_strerror (GpgmeError err);


#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */








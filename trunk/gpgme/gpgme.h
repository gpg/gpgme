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
} GpgmeError;

typedef enum {
    GPGME_DATA_TYPE_NONE = 0,
    GPGME_DATA_TYPE_MEM  = 1,
    GPGME_DATA_TYPE_FD   = 2,
    GPGME_DATA_TYPE_FILE = 3
} GpgmeDataType;


/* Context management */
GpgmeError gpgme_new (GpgmeCtx *r_ctx);
void       gpgme_release ( GpgmeCtx c );
GpgmeCtx   gpgme_wait ( GpgmeCtx c, int hang );

/* Functions to handle recipients */
GpgmeError   gpgme_recipients_new (GpgmeRecipients *r_rset);
void         gpgme_recipients_release ( GpgmeRecipients rset);
GpgmeError   gpgme_recipients_add_name (GpgmeRecipients rset,
                                        const char *name);
unsigned int gpgme_recipients_count ( const GpgmeRecipients rset );

/* Functions to handle data sources */
GpgmeError    gpgme_data_new ( GpgmeData *r_dh,
                               const char *buffer, size_t size, int copy );
void          gpgme_data_release ( GpgmeData dh );
GpgmeDataType gpgme_data_get_type ( GpgmeData dh );
GpgmeError    gpgme_data_rewind ( GpgmeData dh );
GpgmeError    gpgme_data_read ( GpgmeData dh,
                                char *buffer, size_t length, size_t *nread );



/* Basic GnuPG functions */
GpgmeError gpgme_op_encrypt_start ( GpgmeCtx c, GpgmeRecipients recp,
                                    GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_verify_start ( GpgmeCtx c,
                                   GpgmeData sig, GpgmeData text );


/* Key management functions */
GpgmeError gpgme_op_keylist_start ( GpgmeCtx c,
                                    const char *pattern, int secret_only );
GpgmeError gpgme_op_keylist_next ( GpgmeCtx c, GpgmeKey *r_key );


/* Convenience functions for syncronous usage */
GpgmeError gpgme_op_encrypt ( GpgmeCtx c, GpgmeRecipients recp,
                              GpgmeData in, GpgmeData out );
GpgmeError gpgme_op_verify ( GpgmeCtx c, GpgmeData sig, GpgmeData text );


/* miscellaneous functions */
const char *gpgme_strerror (GpgmeError err);


#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */








/* gpgme.h -  GnuPG Made Easy
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *      Copyright (C) 2001, 2002 g10 Code GmbH
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

#include <stdio.h> /* For FILE *.  */
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


/* The version of this header should match the one of the library.  Do
   not use this symbol in your application, use gpgme_check_version
   instead.  The purpose of this macro is to let autoconf (using the
   AM_PATH_GPGME macro) check that this header matches the installed
   library.  Warning: Do not edit the next line.  configure will do
   that for you!  */
#define GPGME_VERSION "0.3.7-cvs"


/* The opaque data types used by GPGME.  */

/* The context holds some global state and configration options as
   well as the results of a crypto operation.  */
struct gpgme_context_s;
typedef struct gpgme_context_s *GpgmeCtx;

/* The data object used by GPGME to exchange arbitrary data.  */
struct gpgme_data_s;
typedef struct gpgme_data_s *GpgmeData;

/* A list of recipients to be used in an encryption operation.  */
struct gpgme_recipients_s;
typedef struct gpgme_recipients_s *GpgmeRecipients;

/* A key from the keyring.  */
struct gpgme_key_s;
typedef struct gpgme_key_s *GpgmeKey;

/* A trust item.  */
struct gpgme_trust_item_s;
typedef struct gpgme_trust_item_s *GpgmeTrustItem;


/* The error numbers used by GPGME.  */
typedef enum
  {
    GPGME_EOF                = -1,
    GPGME_No_Error           = 0,
    GPGME_General_Error      = 1,
    GPGME_Out_Of_Core        = 2,
    GPGME_Invalid_Value      = 3,
    GPGME_Busy               = 4,
    GPGME_No_Request         = 5,
    GPGME_Exec_Error         = 6,
    GPGME_Too_Many_Procs     = 7,
    GPGME_Pipe_Error         = 8,
    GPGME_No_Recipients      = 9,
    GPGME_No_Data            = 10,
    GPGME_Conflict           = 11,
    GPGME_Not_Implemented    = 12,
    GPGME_Read_Error         = 13,
    GPGME_Write_Error        = 14,
    GPGME_Invalid_Type       = 15,
    GPGME_Invalid_Mode       = 16,
    GPGME_File_Error         = 17,  /* errno is set in this case.  */
    GPGME_Decryption_Failed  = 18,
    GPGME_No_Passphrase      = 19,
    GPGME_Canceled           = 20,
    GPGME_Invalid_Key        = 21,
    GPGME_Invalid_Engine     = 22,
    GPGME_Invalid_Recipients = 23
  }
GpgmeError;

/* The possible types of GpgmeData objects.  */
typedef enum
  {
    GPGME_DATA_TYPE_NONE = 0,
    GPGME_DATA_TYPE_MEM  = 1,
    GPGME_DATA_TYPE_FD   = 2,
    GPGME_DATA_TYPE_FILE = 3,
    GPGME_DATA_TYPE_CB   = 4
  }
GpgmeDataType;

/* The possible encoding mode of GpgmeData objects.  */
typedef enum
  {
    GPGME_DATA_ENCODING_NONE   = 0, /* i.e. not specified */
    GPGME_DATA_ENCODING_BINARY = 1,
    GPGME_DATA_ENCODING_BASE64 = 2, 
    GPGME_DATA_ENCODING_ARMOR  = 3 /* Either PEM or OpenPGP Armor */
  }
GpgmeDataEncoding;

/* The possible signature stati.  */
typedef enum
  {
    GPGME_SIG_STAT_NONE  = 0,
    GPGME_SIG_STAT_GOOD  = 1,
    GPGME_SIG_STAT_BAD   = 2,
    GPGME_SIG_STAT_NOKEY = 3,
    GPGME_SIG_STAT_NOSIG = 4,
    GPGME_SIG_STAT_ERROR = 5,
    GPGME_SIG_STAT_DIFF  = 6,
    GPGME_SIG_STAT_GOOD_EXP = 7,
    GPGME_SIG_STAT_GOOD_EXPKEY = 8
  }
GpgmeSigStat;

/* The available signature modes.  */
typedef enum
  {
    GPGME_SIG_MODE_NORMAL = 0,
    GPGME_SIG_MODE_DETACH = 1,
    GPGME_SIG_MODE_CLEAR  = 2
  }
GpgmeSigMode;

/* The available key and signature attributes.  */
typedef enum
  {
    GPGME_ATTR_KEYID        = 1,
    GPGME_ATTR_FPR          = 2,
    GPGME_ATTR_ALGO         = 3,
    GPGME_ATTR_LEN          = 4,
    GPGME_ATTR_CREATED      = 5,
    GPGME_ATTR_EXPIRE       = 6,
    GPGME_ATTR_OTRUST       = 7,
    GPGME_ATTR_USERID       = 8,
    GPGME_ATTR_NAME         = 9,
    GPGME_ATTR_EMAIL        = 10,
    GPGME_ATTR_COMMENT      = 11,
    GPGME_ATTR_VALIDITY     = 12,
    GPGME_ATTR_LEVEL        = 13,
    GPGME_ATTR_TYPE         = 14,
    GPGME_ATTR_IS_SECRET    = 15,
    GPGME_ATTR_KEY_REVOKED  = 16,
    GPGME_ATTR_KEY_INVALID  = 17,
    GPGME_ATTR_UID_REVOKED  = 18,
    GPGME_ATTR_UID_INVALID  = 19,
    GPGME_ATTR_KEY_CAPS     = 20,
    GPGME_ATTR_CAN_ENCRYPT  = 21,
    GPGME_ATTR_CAN_SIGN     = 22,
    GPGME_ATTR_CAN_CERTIFY  = 23,
    GPGME_ATTR_KEY_EXPIRED  = 24,
    GPGME_ATTR_KEY_DISABLED = 25,
    GPGME_ATTR_SERIAL       = 26,
    GPGME_ATTR_ISSUER       = 27,
    GPGME_ATTR_CHAINID      = 28,
    GPGME_ATTR_SIG_STATUS   = 29
  }
GpgmeAttr;

/* The available validities for a trust item or key.  */
typedef enum
  {
    GPGME_VALIDITY_UNKNOWN   = 0,
    GPGME_VALIDITY_UNDEFINED = 1,
    GPGME_VALIDITY_NEVER     = 2,
    GPGME_VALIDITY_MARGINAL  = 3,
    GPGME_VALIDITY_FULL      = 4,
    GPGME_VALIDITY_ULTIMATE  = 5
  }
GpgmeValidity;

/* The available protocols.  */
typedef enum
  {
    GPGME_PROTOCOL_OpenPGP = 0,  /* The default mode.  */
    GPGME_PROTOCOL_CMS     = 1,
    GPGME_PROTOCOL_AUTO    = 2
  }
GpgmeProtocol;


/* The available keylist mode flags.  */
#define GPGME_KEYLIST_MODE_LOCAL 1
#define GPGME_KEYLIST_MODE_EXTERN 2


/* Types for callback functions.  */

/* Request a passphrase from the user.  */
typedef const char *(*GpgmePassphraseCb) (void *hook, const char *desc,
					  void **r_hd);

/* Inform the user about progress made.  */
typedef void (*GpgmeProgressCb) (void *opaque, const char *what,
				 int type, int current, int total);


/* Context management functions.  */

/* Create a new context and return it in CTX.  */
GpgmeError gpgme_new (GpgmeCtx *ctx);

/* Release the context CTX.  */
void gpgme_release (GpgmeCtx ctx);

/* Retrieve more info about performed signature check.  */
char *gpgme_get_notation (GpgmeCtx ctx);

/* Set the protocol to be used by CTX to PROTO.  */
GpgmeError gpgme_set_protocol (GpgmeCtx ctx, GpgmeProtocol proto);

/* Get the protocol used with CTX */
GpgmeProtocol gpgme_get_protocol (GpgmeCtx ctx);

/* If YES is non-zero, enable armor mode in CTX, disable it otherwise.  */
void gpgme_set_armor (GpgmeCtx ctx, int yes);

/* Return non-zero if armor mode is set in CTX.  */
int gpgme_get_armor (GpgmeCtx ctx);

/* If YES is non-zero, enable text mode in CTX, disable it otherwise.  */
void gpgme_set_textmode (GpgmeCtx ctx, int yes);

/* Return non-zero if text mode is set in CTX.  */
int gpgme_get_textmode (GpgmeCtx ctx);

/* Include up to NR_OF_CERTS certificates in an S/MIME message.  */
void gpgme_set_include_certs (GpgmeCtx ctx, int nr_of_certs);

/* Return the number of certs to include in an S/MIME message.  */
int gpgme_get_include_certs (GpgmeCtx ctx);

/* Set keylist mode in CTX to MODE.  */
GpgmeError gpgme_set_keylist_mode (GpgmeCtx ctx, int mode);

/* Get keylist mode in CTX.  */
int gpgme_get_keylist_mode (GpgmeCtx ctx);

/* Set the passphrase callback function in CTX to CB.  HOOK_VALUE is
   passed as first argument to the passphrase callback function.  */
void gpgme_set_passphrase_cb (GpgmeCtx ctx,
                              GpgmePassphraseCb cb, void *hook_value);

/* Get the current passphrase callback function in *CB and the current
   hook value in *HOOK_VALUE.  */
void gpgme_get_passphrase_cb (GpgmeCtx ctx, GpgmePassphraseCb *cb,
			      void **hook_value);

/* Set the progress callback function in CTX to CB.  HOOK_VALUE is
   passed as first argument to the progress callback function.  */
void gpgme_set_progress_cb (GpgmeCtx c, GpgmeProgressCb cb, void *hook_value);

/* Get the current progress callback function in *CB and the current
   hook value in *HOOK_VALUE.  */
void gpgme_get_progress_cb (GpgmeCtx ctx, GpgmeProgressCb *cb,
			    void **hook_value);

/* Delete all signers from CTX.  */
void gpgme_signers_clear (GpgmeCtx ctx);

/* Add KEY to list of signers in CTX.  */
GpgmeError gpgme_signers_add (GpgmeCtx ctx, const GpgmeKey key);

/* Return the SEQth signer's key in CTX.  */
GpgmeKey gpgme_signers_enum (const GpgmeCtx ctx, int seq);

/* Retrieve the signature status of signature IDX in CTX after a
   successful verify operation in R_STAT (if non-null).  The creation
   time stamp of the signature is returned in R_CREATED (if non-null).
   The function returns a string containing the fingerprint.  */
const char *gpgme_get_sig_status (GpgmeCtx ctx, int idx,
                                  GpgmeSigStat *r_stat, time_t *r_created);

/* Retrieve certain attributes of a signature.  IDX is the index
   number of the signature after a successful verify operation.  WHAT
   is an attribute where GPGME_ATTR_EXPIRE is probably the most useful
   one.  RESERVED must be passed as 0. */
unsigned long gpgme_get_sig_ulong_attr (GpgmeCtx c, int idx,
                                        GpgmeAttr what, int reserved);
const char *gpgme_get_sig_string_attr (GpgmeCtx c, int idx,
                                      GpgmeAttr what, int reserved);


/* Get the key used to create signature IDX in CTX and return it in
   R_KEY.  */
GpgmeError gpgme_get_sig_key (GpgmeCtx ctx, int idx, GpgmeKey *r_key);

/* Return a string with more info about the last crypto operating in CTX.
   RESERVED should be zero.  The user has to free the string.  */
char *gpgme_get_op_info (GpgmeCtx ctx, int reserved);


/* Run control.  */

/* Cancel a pending operation in CTX.  */
void       gpgme_cancel (GpgmeCtx ctx);

/* Process the pending operation and, if HANG is non-zero, wait for
   the pending operation to finish.  */
GpgmeCtx gpgme_wait (GpgmeCtx ctx, GpgmeError *status, int hang);


/* Functions to handle recipients.  */

/* Create a new recipients set and return it in R_RSET.  */
GpgmeError gpgme_recipients_new (GpgmeRecipients *r_rset);

/* Release the recipients set RSET.  */
void gpgme_recipients_release (GpgmeRecipients rset);

/* Add NAME to the recipients set RSET.  */
GpgmeError gpgme_recipients_add_name (GpgmeRecipients rset, const char *name);

/* Add NAME with validity AL to the recipients set RSET.  */
GpgmeError gpgme_recipients_add_name_with_validity (GpgmeRecipients rset,
                                                    const char *name,
						    GpgmeValidity val);

/* Return the number of recipients in RSET.  */
unsigned int gpgme_recipients_count (const GpgmeRecipients rset);

/* Create a new enumeration handle for the recipients set RSET and
   return it in ITER.  */
GpgmeError gpgme_recipients_enum_open (const GpgmeRecipients rset,
				       void **iter);

/* Return the next recipient from the recipient set RSET in the
   enumerator ITER.  */
const char *gpgme_recipients_enum_read (const GpgmeRecipients rset,
					void **iter);

/* Destroy the enumerator ITER for the recipient set RSET.  */
GpgmeError gpgme_recipients_enum_close (const GpgmeRecipients rset,
					void **iter);


/* Functions to handle data objects.  */

/* Create a new data buffer and return it in R_DH.  */
GpgmeError gpgme_data_new (GpgmeData *r_dh);

/* Create a new data buffer filled with SIZE bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  */
GpgmeError gpgme_data_new_from_mem (GpgmeData *r_dh,
				    const char *buffer, size_t size,
				    int copy);

/* Create a new data buffer which retrieves the data from the callback
   function READ_CB.  */
GpgmeError gpgme_data_new_with_read_cb (GpgmeData *r_dh,
					int (*read_cb) (void*,char *,size_t,size_t*),
					void *read_cb_value);

/* Create a new data buffer filled with the content of file FNAME.
   COPY must be non-zero (delayed reads are not supported yet).  */
GpgmeError gpgme_data_new_from_file (GpgmeData *r_dh,
				     const char *fname,
				     int copy);

/* Create a new data buffer filled with LENGTH bytes starting from
   OFFSET within the file FNAME or stream FP (exactly one must be
   non-zero).  */
GpgmeError gpgme_data_new_from_filepart (GpgmeData *r_dh,
					 const char *fname, FILE *fp,
					 off_t offset, size_t length);

/* Destroy the data buffer DH.  */
void gpgme_data_release (GpgmeData dh);

/* Destroy the data buffer DH and return a pointer to its content.
   The memory has be to released with free by the user.  It's size is
   returned in R_LEN.  */
char *gpgme_data_release_and_get_mem (GpgmeData dh, size_t *r_len);

/* Return the type of the data buffer DH.  */
GpgmeDataType gpgme_data_get_type (GpgmeData dh);

/* Return the encoding attribute of the data buffer DH */
GpgmeDataEncoding gpgme_data_get_encoding (GpgmeData dh);

/* Set the encoding attribute of data buffer DH to ENC */
GpgmeError gpgme_data_set_encoding (GpgmeData dh, GpgmeDataEncoding enc);

/* Reset the read pointer in DH.  */
GpgmeError gpgme_data_rewind (GpgmeData dh);

/* Read LENGTH bytes from the data object DH and store them in the
   memory starting at BUFFER.  The number of bytes actually read is
   returned in NREAD.  */
GpgmeError gpgme_data_read (GpgmeData dh, void *buffer,
			    size_t length, size_t *nread);

/* Write LENGTH bytes starting from BUFFER into the data object DH.  */
GpgmeError gpgme_data_write (GpgmeData dh, const void *buffer, size_t length);


/* Key and trust functions.  */

/* Acquire a reference to KEY.  */
void gpgme_key_ref (GpgmeKey key);

/* Release a reference to KEY.  If this was the last one the key is
   destroyed.  */
void gpgme_key_unref (GpgmeKey key);
void gpgme_key_release (GpgmeKey key);

/* Get the data from key KEY in a XML string, which has to be released
   with free by the user.  */
char *gpgme_key_get_as_xml (GpgmeKey key);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by a string.  IDX specifies a running index if the
   attribute appears more than once in the key.  */
const char *gpgme_key_get_string_attr (GpgmeKey key, GpgmeAttr what,
				       const void *reserved, int idx);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an unsigned integer.  IDX specifies a running
   index if the attribute appears more than once in the key.  */
unsigned long gpgme_key_get_ulong_attr (GpgmeKey key, GpgmeAttr what,
					const void *reserved, int idx);

/* Release the trust item ITEM.  */
void gpgme_trust_item_release (GpgmeTrustItem item);

/* Return the value of the attribute WHAT of ITEM, which has to be
   representable by a string.  IDX specifies a running index if the
   attribute appears more than once in the key.  */
const char *gpgme_trust_item_get_string_attr (GpgmeTrustItem item,
					      GpgmeAttr what,
					      const void *reserved, int idx);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an integer.  IDX specifies a running index if the
   attribute appears more than once in the key.  */
int gpgme_trust_item_get_int_attr (GpgmeTrustItem item, GpgmeAttr what,
				   const void *reserved, int idx);


/* Crypto operation function.  */

/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
   store the resulting ciphertext in CIPHER.  */
GpgmeError gpgme_op_encrypt_start (GpgmeCtx ctx,
				   GpgmeRecipients recp,
				   GpgmeData plain, GpgmeData cipher);
GpgmeError gpgme_op_encrypt (GpgmeCtx ctx,
			     GpgmeRecipients recp,
			     GpgmeData plain, GpgmeData cipher);

/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
   store the resulting ciphertext in CIPHER.  Also sign the ciphertext
   with the signers in CTX.  */
GpgmeError gpgme_op_encrypt_sign_start (GpgmeCtx ctx,
					GpgmeRecipients recp,
					GpgmeData plain, GpgmeData cipher);
GpgmeError gpgme_op_encrypt_sign (GpgmeCtx ctx,
				  GpgmeRecipients recp,
				  GpgmeData plain, GpgmeData cipher);

/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
GpgmeError gpgme_op_decrypt_start (GpgmeCtx ctx,
				   GpgmeData cipher, GpgmeData plain);
GpgmeError gpgme_op_decrypt (GpgmeCtx ctx,
			     GpgmeData cipher, GpgmeData plain);

/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
GpgmeError gpgme_op_decrypt_verify_start (GpgmeCtx ctx,
					  GpgmeData cipher, GpgmeData plain);
GpgmeError gpgme_op_decrypt_verify (GpgmeCtx ctx,
				    GpgmeData cipher, GpgmeData plain,
				    GpgmeSigStat *r_status);

/* Sign the plaintext PLAIN and store the signature in SIG.  Only
   detached signatures are supported for now.  */
GpgmeError gpgme_op_sign_start (GpgmeCtx ctx,
				GpgmeData plain, GpgmeData sig,
				GpgmeSigMode mode);
GpgmeError gpgme_op_sign (GpgmeCtx ctx,
			  GpgmeData plain, GpgmeData sig,
			  GpgmeSigMode mode);

/* Verify within CTX that SIG is a valid signature for TEXT.  */
GpgmeError gpgme_op_verify_start (GpgmeCtx ctx,
				  GpgmeData sig, GpgmeData text);
GpgmeError gpgme_op_verify (GpgmeCtx ctx,
			    GpgmeData sig, GpgmeData text,
			    GpgmeSigStat *r_status);

/* Import the key in KEYDATA into the keyring.  */
GpgmeError gpgme_op_import_start (GpgmeCtx ctx, GpgmeData keydata);
GpgmeError gpgme_op_import (GpgmeCtx ctx, GpgmeData keydata);

/* Export the keys listed in RECP into KEYDATA.  */
GpgmeError gpgme_op_export_start (GpgmeCtx ctx, GpgmeRecipients recp,
				  GpgmeData keydata);
GpgmeError gpgme_op_export (GpgmeCtx ctx, GpgmeRecipients recp,
			    GpgmeData keydata);

/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
GpgmeError gpgme_op_genkey_start (GpgmeCtx ctx, const char *parms,
				  GpgmeData pubkey, GpgmeData seckey);
GpgmeError gpgme_op_genkey (GpgmeCtx ctx, const char *parms,
			    GpgmeData pubkey, GpgmeData seckey);

/* Delete KEY from the keyring.  If ALLOW_SECRET is non-zero, secret
   keys are also deleted.  */
GpgmeError gpgme_op_delete_start (GpgmeCtx ctx, const GpgmeKey key,
				  int allow_secret);
GpgmeError gpgme_op_delete (GpgmeCtx ctx, const GpgmeKey key,
			    int allow_secret);


/* Key management functions */

/* Start a keylist operation within CTX, searching for keys which
   match PATTERN.  If SECRET_ONLY is true, only secret keys are
   returned.  */
GpgmeError gpgme_op_keylist_start (GpgmeCtx ctx,
				   const char *pattern, int secret_only);
GpgmeError gpgme_op_keylist_ext_start (GpgmeCtx ctx, const char *pattern[],
		                       int secret_only, int reserved);

/* Return the next key from the keylist in R_KEY.  */
GpgmeError gpgme_op_keylist_next (GpgmeCtx ctx, GpgmeKey *r_key);

/* Terminate a pending keylist operation within CTX.  */
GpgmeError gpgme_op_keylist_end (GpgmeCtx ctx);


/* Start a trustlist operation within CTX, searching for trust items
   which match PATTERN.  */
GpgmeError gpgme_op_trustlist_start (GpgmeCtx ctx,
				     const char *pattern, int max_level);

/* Return the next trust item from the trustlist in R_ITEM.  */
GpgmeError gpgme_op_trustlist_next (GpgmeCtx ctx, GpgmeTrustItem *r_item);

/* Terminate a pending trustlist operation within CTX.  */
GpgmeError gpgme_op_trustlist_end (GpgmeCtx ctx);


/* Various functions.  */

/* Check that the library fulfills the version requirement.  */
const char *gpgme_check_version (const char *req_version);

/* Check that the backend engine is available.  DEPRECATED.  */
GpgmeError  gpgme_check_engine (void);

/* Retrieve information about the backend engines.  */
const char *gpgme_get_engine_info (void);

/* Return a string describing ERR.  */
const char *gpgme_strerror (GpgmeError err);

/* Register an idle function.  */
typedef void (*GpgmeIdleFunc)(void);
GpgmeIdleFunc gpgme_register_idle (GpgmeIdleFunc idle);


/* Engine support functions.  */

/* Verify that the engine implementing PROTO is installed and
   available.  */
GpgmeError gpgme_engine_check_version (GpgmeProtocol proto);


#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */

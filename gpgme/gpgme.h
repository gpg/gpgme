/* gpgme.h - Public interface to GnuPG Made Easy.
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

#ifndef GPGME_H
#define GPGME_H

#include <stdio.h> /* For FILE *.  */
#ifdef _MSC_VER
  typedef long off_t;
  typedef long ssize_t;
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
#define GPGME_VERSION "0.4.1"


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
    GPGME_EOF                     = -1,
    GPGME_No_Error                = 0x0000,
    GPGME_General_Error           = 0x0001,
    GPGME_Out_Of_Core             = 0x0002,
    GPGME_Invalid_Value           = 0x0003,
    GPGME_Exec_Error              = 0x0004,
    GPGME_Too_Many_Procs          = 0x0005,
    GPGME_Pipe_Error              = 0x0006,
    GPGME_No_Data                 = 0x0007,
    GPGME_Conflict                = 0x0008,
    GPGME_Not_Implemented         = 0x0009,
    GPGME_Read_Error              = 0x000a,
    GPGME_Write_Error             = 0x000b,
    GPGME_File_Error              = 0x000c, /* errno is set in this case.  */
    GPGME_Decryption_Failed       = 0x000d,
    GPGME_Bad_Passphrase          = 0x000e,
    GPGME_Canceled                = 0x000f,
    GPGME_Invalid_Key             = 0x0010,
    GPGME_Invalid_Engine          = 0x0011,
    GPGME_No_UserID               = 0x0012,
    GPGME_Invalid_UserID          = 0x0013,

    /* Reasons for invalid user id.  */
    GPGME_Unknown_Reason          = 0x0100,
    GPGME_Not_Found               = 0x0101,
    GPGME_Ambiguous_Specification = 0x0102,
    GPGME_Wrong_Key_Usage         = 0x0103,
    GPGME_Key_Revoked             = 0x0104,
    GPGME_Key_Expired             = 0x0105,
    GPGME_No_CRL_Known            = 0x0106,
    GPGME_CRL_Too_Old             = 0x0107,
    GPGME_Policy_Mismatch         = 0x0108,
    GPGME_No_Secret_Key           = 0x0109,
    GPGME_Key_Not_Trusted         = 0x010a,
    
    /* Import problems.  */
    GPGME_Issuer_Missing          = 0x0200,
    GPGME_Chain_Too_Long          = 0x0201,

    /* Verification problems.  */
    GPGME_Unsupported_Algorithm   = 0x0300,
    GPGME_Sig_Expired             = 0x0301,
    GPGME_Bad_Signature           = 0x0302,
    GPGME_No_Public_Key           = 0x0303,

    /* Deprecated.  */
    GPGME_Busy                    = -2,
    GPGME_No_Request              = -3
  }
GpgmeError;

#define GPGME_No_Recipients	GPGME_No_UserID
#define GPGME_Invalid_Recipient	GPGME_Invalid_UserID
#define GPGME_No_Passphrase	GPGME_Bad_Passphrase

/* The possible encoding mode of GpgmeData objects.  */
typedef enum
  {
    GPGME_DATA_ENCODING_NONE   = 0,	/* I.e. not specified.  */
    GPGME_DATA_ENCODING_BINARY = 1,
    GPGME_DATA_ENCODING_BASE64 = 2,
    GPGME_DATA_ENCODING_ARMOR  = 3	/* Either PEM or OpenPGP Armor.  */
  }
GpgmeDataEncoding;


/* Public key algorithms from libgcrypt.  */
typedef enum
  {
    GPGME_PK_RSA   = 1,
    GPGME_PK_RSA_E = 2,
    GPGME_PK_RSA_S = 3,
    GPGME_PK_ELG_E = 16,
    GPGME_PK_DSA   = 17,
    GPGME_PK_ELG   = 20
  }
GpgmePubKeyAlgo;


/* Hash algorithms from libgcrypt.  */
typedef enum
  {
    GPGME_MD_NONE          = 0,  
    GPGME_MD_MD5           = 1,
    GPGME_MD_SHA1          = 2,
    GPGME_MD_RMD160        = 3,
    GPGME_MD_MD2           = 5,
    GPGME_MD_TIGER         = 6,   /* TIGER/192. */
    GPGME_MD_HAVAL         = 7,   /* HAVAL, 5 pass, 160 bit. */
    GPGME_MD_SHA256        = 8,
    GPGME_MD_SHA384        = 9,
    GPGME_MD_SHA512        = 10,
    GPGME_MD_MD4           = 301,
    GPGME_MD_CRC32	   = 302,
    GPGME_MD_CRC32_RFC1510 = 303,
    GPGME_MD_CRC24_RFC2440 = 304
  }
GpgmeHashAlgo;


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

/* Flags used with the GPGME_ATTR_SIG_SUMMARY.  */
enum 
  {
    GPGME_SIGSUM_VALID       = 0x0001,  /* The signature is fully valid.  */
    GPGME_SIGSUM_GREEN       = 0x0002,  /* The signature is good.  */
    GPGME_SIGSUM_RED         = 0x0004,  /* The signature is bad.  */
    GPGME_SIGSUM_KEY_REVOKED = 0x0010,  /* One key has been revoked.  */
    GPGME_SIGSUM_KEY_EXPIRED = 0x0020,  /* One key has expired.  */
    GPGME_SIGSUM_SIG_EXPIRED = 0x0040,  /* The signature has expired.  */
    GPGME_SIGSUM_KEY_MISSING = 0x0080,  /* Can't verify: key missing.  */
    GPGME_SIGSUM_CRL_MISSING = 0x0100,  /* CRL not available.  */
    GPGME_SIGSUM_CRL_TOO_OLD = 0x0200,  /* Available CRL is too old.  */
    GPGME_SIGSUM_BAD_POLICY  = 0x0400,  /* A policy was not met.  */
    GPGME_SIGSUM_SYS_ERROR   = 0x0800   /* A system error occured.  */
  };


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
    GPGME_ATTR_SIG_STATUS   = 29,
    GPGME_ATTR_ERRTOK       = 30,
    GPGME_ATTR_SIG_SUMMARY  = 31,
    GPGME_ATTR_SIG_CLASS    = 32
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
  }
GpgmeProtocol;


/* The possible stati for the edit operation.  */
typedef enum
  {
    GPGME_STATUS_EOF,
    /* mkstatus processing starts here */
    GPGME_STATUS_ENTER,
    GPGME_STATUS_LEAVE,
    GPGME_STATUS_ABORT,

    GPGME_STATUS_GOODSIG,
    GPGME_STATUS_BADSIG,
    GPGME_STATUS_ERRSIG,

    GPGME_STATUS_BADARMOR,

    GPGME_STATUS_RSA_OR_IDEA,
    GPGME_STATUS_KEYEXPIRED,
    GPGME_STATUS_KEYREVOKED,

    GPGME_STATUS_TRUST_UNDEFINED,
    GPGME_STATUS_TRUST_NEVER,
    GPGME_STATUS_TRUST_MARGINAL,
    GPGME_STATUS_TRUST_FULLY,
    GPGME_STATUS_TRUST_ULTIMATE,

    GPGME_STATUS_SHM_INFO,
    GPGME_STATUS_SHM_GET,
    GPGME_STATUS_SHM_GET_BOOL,
    GPGME_STATUS_SHM_GET_HIDDEN,

    GPGME_STATUS_NEED_PASSPHRASE,
    GPGME_STATUS_VALIDSIG,
    GPGME_STATUS_SIG_ID,
    GPGME_STATUS_ENC_TO,
    GPGME_STATUS_NODATA,
    GPGME_STATUS_BAD_PASSPHRASE,
    GPGME_STATUS_NO_PUBKEY,
    GPGME_STATUS_NO_SECKEY,
    GPGME_STATUS_NEED_PASSPHRASE_SYM,
    GPGME_STATUS_DECRYPTION_FAILED,
    GPGME_STATUS_DECRYPTION_OKAY,
    GPGME_STATUS_MISSING_PASSPHRASE,
    GPGME_STATUS_GOOD_PASSPHRASE,
    GPGME_STATUS_GOODMDC,
    GPGME_STATUS_BADMDC,
    GPGME_STATUS_ERRMDC,
    GPGME_STATUS_IMPORTED,
    GPGME_STATUS_IMPORT_OK,
    GPGME_STATUS_IMPORT_PROBLEM,
    GPGME_STATUS_IMPORT_RES,
    GPGME_STATUS_FILE_START,
    GPGME_STATUS_FILE_DONE,
    GPGME_STATUS_FILE_ERROR,

    GPGME_STATUS_BEGIN_DECRYPTION,
    GPGME_STATUS_END_DECRYPTION,
    GPGME_STATUS_BEGIN_ENCRYPTION,
    GPGME_STATUS_END_ENCRYPTION,

    GPGME_STATUS_DELETE_PROBLEM,
    GPGME_STATUS_GET_BOOL,
    GPGME_STATUS_GET_LINE,
    GPGME_STATUS_GET_HIDDEN,
    GPGME_STATUS_GOT_IT,
    GPGME_STATUS_PROGRESS,
    GPGME_STATUS_SIG_CREATED,
    GPGME_STATUS_SESSION_KEY,
    GPGME_STATUS_NOTATION_NAME,
    GPGME_STATUS_NOTATION_DATA,
    GPGME_STATUS_POLICY_URL,
    GPGME_STATUS_BEGIN_STREAM,
    GPGME_STATUS_END_STREAM,
    GPGME_STATUS_KEY_CREATED,
    GPGME_STATUS_USERID_HINT,
    GPGME_STATUS_UNEXPECTED,
    GPGME_STATUS_INV_RECP,
    GPGME_STATUS_NO_RECP,
    GPGME_STATUS_ALREADY_SIGNED,
    GPGME_STATUS_SIGEXPIRED,
    GPGME_STATUS_EXPSIG,
    GPGME_STATUS_EXPKEYSIG,
    GPGME_STATUS_TRUNCATED,
    GPGME_STATUS_ERROR
  }
GpgmeStatusCode;

/* The available keylist mode flags.  */
#define GPGME_KEYLIST_MODE_LOCAL  1
#define GPGME_KEYLIST_MODE_EXTERN 2
#define GPGME_KEYLIST_MODE_SIGS   4

/* The engine information structure.  */
struct _gpgme_engine_info
{
  struct _gpgme_engine_info *next;

  /* The protocol ID.  */
  GpgmeProtocol protocol;

  /* The file name of the engine binary.  */
  const char *file_name;

  /* The version string of the installed engine.  */
  const char *version;

  /* The minimum version required for GPGME.  */
  const char *req_version;
};
typedef struct _gpgme_engine_info *GpgmeEngineInfo;


/* Types for callback functions.  */

/* Request a passphrase from the user.  */
typedef GpgmeError (*GpgmePassphraseCb) (void *hook, const char *desc,
					 void **r_hd, const char **result);

/* Inform the user about progress made.  */
typedef void (*GpgmeProgressCb) (void *opaque, const char *what,
				 int type, int current, int total);

/* Interact with the user about an edit operation.  */
typedef GpgmeError (*GpgmeEditCb) (void *opaque, GpgmeStatusCode status,
				   const char *args, const char **reply);

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

/* Get the string describing protocol PROTO, or NULL if invalid.  */
const char *gpgme_get_protocol_name (GpgmeProtocol proto);

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


/* Return a statically allocated string with the name of the public
   key algorithm ALGO, or NULL if that name is not known.  */
const char *gpgme_pubkey_algo_name (GpgmePubKeyAlgo algo);

/* Return a statically allocated string with the name of the hash
   algorithm ALGO, or NULL if that name is not known.  */
const char *gpgme_hash_algo_name (GpgmeHashAlgo algo);


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
   one.  WHATIDX is to be passed as 0 for most attributes . */
unsigned long gpgme_get_sig_ulong_attr (GpgmeCtx c, int idx,
                                        GpgmeAttr what, int whatidx);
const char *gpgme_get_sig_string_attr (GpgmeCtx c, int idx,
                                      GpgmeAttr what, int whatidx);


/* Get the key used to create signature IDX in CTX and return it in
   R_KEY.  */
GpgmeError gpgme_get_sig_key (GpgmeCtx ctx, int idx, GpgmeKey *r_key);

/* Return a string with more info about the last crypto operating in CTX.
   RESERVED should be zero.  The user has to free the string.  */
char *gpgme_get_op_info (GpgmeCtx ctx, int reserved);


/* Run control.  */

/* The type of an I/O callback function.  */
typedef GpgmeError (*GpgmeIOCb) (void *data, int fd);

/* The type of a function that can register FNC as the I/O callback
   function for the file descriptor FD with direction dir (0: for writing,
   1: for reading).  FNC_DATA should be passed as DATA to FNC.  The
   function should return a TAG suitable for the corresponding
   GpgmeRemoveIOCb, and an error value.  */
typedef GpgmeError (*GpgmeRegisterIOCb) (void *data, int fd, int dir,
					 GpgmeIOCb fnc, void *fnc_data,
					 void **tag);

/* The type of a function that can remove a previously registered I/O
   callback function given TAG as returned by the register
   function.  */
typedef void (*GpgmeRemoveIOCb) (void *tag);

typedef enum { GPGME_EVENT_START,
	       GPGME_EVENT_DONE,
	       GPGME_EVENT_NEXT_KEY,
	       GPGME_EVENT_NEXT_TRUSTITEM } GpgmeEventIO;

/* The type of a function that is called when a context finished an
   operation.  */
typedef void (*GpgmeEventIOCb) (void *data, GpgmeEventIO type,
				void *type_data);

struct GpgmeIOCbs
{
  GpgmeRegisterIOCb add;
  void *add_priv;
  GpgmeRemoveIOCb remove;
  GpgmeEventIOCb event;
  void *event_priv;
};

/* Set the I/O callback functions in CTX to IO_CBS.  */
void gpgme_set_io_cbs (GpgmeCtx ctx, struct GpgmeIOCbs *io_cbs);

/* Get the current I/O callback functions.  */
void gpgme_get_io_cbs (GpgmeCtx ctx, struct GpgmeIOCbs *io_cbs);

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

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle HANDLE.  Return the number of characters read, 0 on EOF
   and -1 on error.  If an error occurs, errno is set.  */
typedef ssize_t (*GpgmeDataReadCb) (void *handle, void *buffer, size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle HANDLE.  Return the number of characters written, or -1
   on error.  If an error occurs, errno is set.  */
typedef ssize_t (*GpgmeDataWriteCb) (void *handle, const void *buffer,
				     size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle HANDLE to OFFSET, relativ to
   WHENCE.  */
typedef off_t (*GpgmeDataSeekCb) (void *handle, off_t offset, int whence);

/* Close the data object with the handle DL.  */
typedef void (*GpgmeDataReleaseCb) (void *handle);

struct GpgmeDataCbs
{
  GpgmeDataReadCb read;
  GpgmeDataWriteCb write;
  GpgmeDataSeekCb seek;
  GpgmeDataReleaseCb release;
};

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
ssize_t gpgme_data_read (GpgmeData dh, void *buffer, size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
ssize_t gpgme_data_write (GpgmeData dh, const void *buffer, size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
off_t gpgme_data_seek (GpgmeData dh, off_t offset, int whence);

/* Create a new data buffer and return it in R_DH.  */
GpgmeError gpgme_data_new (GpgmeData *r_dh);

/* Destroy the data buffer DH.  */
void gpgme_data_release (GpgmeData dh);

/* Create a new data buffer filled with SIZE bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  */
GpgmeError gpgme_data_new_from_mem (GpgmeData *r_dh,
				    const char *buffer, size_t size,
				    int copy);

/* Destroy the data buffer DH and return a pointer to its content.
   The memory has be to released with free by the user.  It's size is
   returned in R_LEN.  */
char *gpgme_data_release_and_get_mem (GpgmeData dh, size_t *r_len);

GpgmeError gpgme_data_new_from_cbs (GpgmeData *dh,
				    struct GpgmeDataCbs *cbs,
				    void *handle);

GpgmeError gpgme_data_new_from_fd (GpgmeData *dh, int fd);

GpgmeError gpgme_data_new_from_stream (GpgmeData *dh, FILE *stream);

/* Return the encoding attribute of the data buffer DH */
GpgmeDataEncoding gpgme_data_get_encoding (GpgmeData dh);

/* Set the encoding attribute of data buffer DH to ENC */
GpgmeError gpgme_data_set_encoding (GpgmeData dh, GpgmeDataEncoding enc);



/* Create a new data buffer which retrieves the data from the callback
   function READ_CB.  Deprecated, please use gpgme_data_new_from_cbs
   instead.  */
GpgmeError gpgme_data_new_with_read_cb (GpgmeData *r_dh,
					int (*read_cb) (void*,char *,size_t,size_t*),
					void *read_cb_value);

/* Create a new data buffer filled with the content of file FNAME.
   COPY must be non-zero.  For delayed read, please use
   gpgme_data_new_from_fd or gpgme_data_new_from stream instead.  */
GpgmeError gpgme_data_new_from_file (GpgmeData *r_dh,
				     const char *fname,
				     int copy);

/* Create a new data buffer filled with LENGTH bytes starting from
   OFFSET within the file FNAME or stream FP (exactly one must be
   non-zero).  */
GpgmeError gpgme_data_new_from_filepart (GpgmeData *r_dh,
					 const char *fname, FILE *fp,
					 off_t offset, size_t length);

/* Reset the read pointer in DH.  Deprecated, please use
   gpgme_data_seek instead.  */
GpgmeError gpgme_data_rewind (GpgmeData dh);


/* Key and trust functions.  */

/* Get the key with the fingerprint FPR from the key cache or from the
   crypto backend.  If FORCE_UPDATE is true, force a refresh of the
   key from the crypto backend and replace the key in the cache, if
   any.  If SECRET is true, get the secret key.  */
GpgmeError gpgme_get_key (GpgmeCtx ctx, const char *fpr, GpgmeKey *r_key,
			  int secret, int force_update);

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
   representable by a string.  IDX specifies the sub key or
   user ID for attributes related to sub keys or user IDs.  */
const char *gpgme_key_get_string_attr (GpgmeKey key, GpgmeAttr what,
				       const void *reserved, int idx);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an unsigned integer.  IDX specifies the sub key or
   user ID for attributes related to sub keys or user IDs.  */
unsigned long gpgme_key_get_ulong_attr (GpgmeKey key, GpgmeAttr what,
					const void *reserved, int idx);

/* Return the value of the attribute WHAT of a signature on user ID
   UID_IDX in KEY, which has to be representable by a string.  IDX
   specifies the signature.  */
const char *gpgme_key_sig_get_string_attr (GpgmeKey key, int uid_idx,
					   GpgmeAttr what,
					   const void *reserved, int idx);

/* Return the value of the attribute WHAT of a signature on user ID
   UID_IDX in KEY, which has to be representable by an unsigned
   integer string.  IDX specifies the signature.  */
unsigned long gpgme_key_sig_get_ulong_attr (GpgmeKey key, int uid_idx,
					    GpgmeAttr what,
					    const void *reserved, int idx);


/* Release the trust item ITEM.  */
void gpgme_trust_item_release (GpgmeTrustItem item);

/* Return the value of the attribute WHAT of ITEM, which has to be
   representable by a string.  */
const char *gpgme_trust_item_get_string_attr (GpgmeTrustItem item,
					      GpgmeAttr what,
					      const void *reserved, int idx);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an integer.  IDX specifies a running index if the
   attribute appears more than once in the key.  */
int gpgme_trust_item_get_int_attr (GpgmeTrustItem item, GpgmeAttr what,
				   const void *reserved, int idx);

/* Crypto Operations.  */

struct _gpgme_invalid_user_id
{
  struct _gpgme_invalid_user_id *next;
  char *id;
  GpgmeError reason;
};
typedef struct _gpgme_invalid_user_id *GpgmeInvalidUserID;


/* Encryption.  */
struct _gpgme_op_encrypt_result
{
  /* The list of invalid recipients.  */
  GpgmeInvalidUserID invalid_recipients;
};
typedef struct _gpgme_op_encrypt_result *GpgmeEncryptResult;

/* Retrieve a pointer to the result of the encrypt operation.  */
GpgmeEncryptResult gpgme_op_encrypt_result (GpgmeCtx ctx);

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
				    GpgmeData cipher, GpgmeData plain);


/* Signing.  */
struct _gpgme_new_signature
{
  struct _gpgme_new_signature *next;
  GpgmeSigMode type;
  GpgmePubKeyAlgo pubkey_algo;
  GpgmeHashAlgo hash_algo;
  unsigned long class;
  long int created;
  char *fpr;
};
typedef struct _gpgme_new_signature *GpgmeNewSignature;

struct _gpgme_op_sign_result
{
  /* The list of invalid signers.  */
  GpgmeInvalidUserID invalid_signers;
  GpgmeNewSignature signatures;
};
typedef struct _gpgme_op_sign_result *GpgmeSignResult;

/* Retrieve a pointer to the result of the signing operation.  */
GpgmeSignResult gpgme_op_sign_result (GpgmeCtx ctx);

/* Sign the plaintext PLAIN and store the signature in SIG.  */
GpgmeError gpgme_op_sign_start (GpgmeCtx ctx,
				GpgmeData plain, GpgmeData sig,
				GpgmeSigMode mode);
GpgmeError gpgme_op_sign (GpgmeCtx ctx,
			  GpgmeData plain, GpgmeData sig,
			  GpgmeSigMode mode);


/* Verify within CTX that SIG is a valid signature for TEXT.  */
GpgmeError gpgme_op_verify_start (GpgmeCtx ctx, GpgmeData sig,
				  GpgmeData signed_text, GpgmeData plaintext);
GpgmeError gpgme_op_verify (GpgmeCtx ctx, GpgmeData sig,
			    GpgmeData signed_text, GpgmeData plaintext);


enum
  {
    /* The key was new.  */
    GPGME_IMPORT_NEW = 1,

    /* The key contained new user IDs.  */
    GPGME_IMPORT_UID = 2,

    /* The key contained new signatures.  */
    GPGME_IMPORT_SIG = 4,

    /* The key contained new sub keys.  */
    GPGME_IMPORT_SUBKEY	= 8,

    /* The key contained a secret key.  */
    GPGME_IMPORT_SECRET = 16
  };

struct _gpgme_import_status
{
  struct _gpgme_import_status *next;

  /* Fingerprint.  */
  char *fpr;

  /* If a problem occured, the reason why the key could not be
     imported.  Otherwise GPGME_No_Error.  */
  GpgmeError result;

  /* The result of the import, the GPGME_IMPORT_* values bit-wise
     ORed.  0 means the key was already known and no new components
     have been added.  */
  unsigned int status;
};
typedef struct _gpgme_import_status *GpgmeImportStatus;

/* Import.  */
struct _gpgme_op_import_result
{
  /* Number of considered keys.  */
  int considered;

  /* Keys without user ID.  */
  int no_user_id;

  /* Imported keys.  */
  int imported;

  /* Imported RSA keys.  */
  int imported_rsa;

  /* Unchanged keys.  */
  int unchanged;

  /* Number of new user ids.  */
  int new_user_ids;

  /* Number of new sub keys.  */
  int new_sub_keys;

  /* Number of new signatures.  */
  int new_signatures;

  /* Number of new revocations.  */
  int new_revocations;

  /* Number of secret keys read.  */
  int secret_read;

  /* Number of secret keys imported.  */
  int secret_imported;

  /* Number of secret keys unchanged.  */
  int secret_unchanged;

  /* Number of keys not imported.  */
  int not_imported;

  /* List of keys for which an import was attempted.  */
  GpgmeImportStatus imports;
};
typedef struct _gpgme_op_import_result *GpgmeImportResult;

/* Retrieve a pointer to the result of the import operation.  */
GpgmeImportResult gpgme_op_import_result (GpgmeCtx ctx);

/* Import the key in KEYDATA into the keyring.  */
GpgmeError gpgme_op_import_start (GpgmeCtx ctx, GpgmeData keydata);
GpgmeError gpgme_op_import (GpgmeCtx ctx, GpgmeData keydata);
GpgmeError gpgme_op_import_ext (GpgmeCtx ctx, GpgmeData keydata, int *nr);


/* Export the keys listed in RECP into KEYDATA.  */
GpgmeError gpgme_op_export_start (GpgmeCtx ctx, GpgmeRecipients recp,
				  GpgmeData keydata);
GpgmeError gpgme_op_export (GpgmeCtx ctx, GpgmeRecipients recp,
			    GpgmeData keydata);


/* Key generation.  */
struct _gpgme_op_genkey_result
{
  /* A primary key was generated.  */
  unsigned int primary : 1;

  /* A sub key was generated.  */
  unsigned int sub : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 30;

  /* The fingerprint of the generated key.  */
  char *fpr;
};
typedef struct _gpgme_op_genkey_result *GpgmeGenKeyResult;

/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
GpgmeError gpgme_op_genkey_start (GpgmeCtx ctx, const char *parms,
				  GpgmeData pubkey, GpgmeData seckey);
GpgmeError gpgme_op_genkey (GpgmeCtx ctx, const char *parms,
			    GpgmeData pubkey, GpgmeData seckey);

/* Retrieve a pointer to the result of the genkey operation.  */
GpgmeGenKeyResult gpgme_op_genkey_result (GpgmeCtx ctx);


/* Delete KEY from the keyring.  If ALLOW_SECRET is non-zero, secret
   keys are also deleted.  */
GpgmeError gpgme_op_delete_start (GpgmeCtx ctx, const GpgmeKey key,
				  int allow_secret);
GpgmeError gpgme_op_delete (GpgmeCtx ctx, const GpgmeKey key,
			    int allow_secret);

/* Edit the key KEY.  Send status and command requests to FNC and
   output of edit commands to OUT.  */
GpgmeError gpgme_op_edit_start (GpgmeCtx ctx, GpgmeKey key,
			  GpgmeEditCb fnc, void *fnc_value,
			  GpgmeData out);
GpgmeError gpgme_op_edit (GpgmeCtx ctx, GpgmeKey key,
			  GpgmeEditCb fnc, void *fnc_value,
			  GpgmeData out);

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

/* Retrieve information about the backend engines.  */
GpgmeError gpgme_get_engine_info (GpgmeEngineInfo *engine_info);

/* Return a string describing ERR.  */
const char *gpgme_strerror (GpgmeError err);


/* Engine support functions.  */

/* Verify that the engine implementing PROTO is installed and
   available.  */
GpgmeError gpgme_engine_check_version (GpgmeProtocol proto);


#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */

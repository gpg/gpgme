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

#ifdef __GNUC__
#define _GPGME_INLINE __inline__
#elif __STDC_VERSION__ >= 199901L
#define _GPGME_INLINE inline
#else
#define _GPGME_INLINE
#endif

/* Include stdio.h for the FILE type definition.  */
#include <stdio.h>

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
#endif /* __cplusplus */

#include <gpg-error.h>


/* Check for compiler features.  */
#if __GNUC__
#define _GPGME_GCC_VERSION (__GNUC__ * 10000 \
                            + __GNUC_MINOR__ * 100 \
                            + __GNUC_PATCHLEVEL__)

#if _GPGME_GCC_VERSION > 30100
#define _GPGME_DEPRECATED	__attribute__ ((__deprecated__))
#endif
#endif

#ifndef _GPGME_DEPRECATED
#define _GPGME_DEPRECATED
#endif


/* The version of this header should match the one of the library.  Do
   not use this symbol in your application, use gpgme_check_version
   instead.  The purpose of this macro is to let autoconf (using the
   AM_PATH_GPGME macro) check that this header matches the installed
   library.  Warning: Do not edit the next line.  configure will do
   that for you!  */
#define GPGME_VERSION "0.4.4"


/* Some opaque data types used by GPGME.  */

/* The context holds some global state and configration options, as
   well as the results of a crypto operation.  */
struct gpgme_context;
typedef struct gpgme_context *gpgme_ctx_t;

/* The data object is used by GPGME to exchange arbitrary data.  */
struct gpgme_data;
typedef struct gpgme_data *gpgme_data_t;


/* Wrappers for the libgpg-error library.  */

typedef gpg_error_t gpgme_error_t;
typedef gpg_err_code_t gpgme_err_code_t;
typedef gpg_err_source_t gpgme_err_source_t;


static _GPGME_INLINE gpgme_error_t
gpgme_err_make (gpgme_err_source_t source, gpgme_err_code_t code)
{
  return gpg_err_make (source, code);
}


/* The user can define GPGME_ERR_SOURCE_DEFAULT before including this
   file to specify a default source for gpgme_error.  */
#ifndef GPGME_ERR_SOURCE_DEFAULT
#define GPGME_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_USER_1
#endif

static _GPGME_INLINE gpgme_error_t
gpgme_error (gpgme_err_code_t code)
{
  return gpgme_err_make (GPGME_ERR_SOURCE_DEFAULT, code);
}


static _GPGME_INLINE gpgme_err_code_t
gpgme_err_code (gpgme_error_t err)
{
  return gpg_err_code (err);
}


static _GPGME_INLINE gpgme_err_source_t
gpgme_err_source (gpgme_error_t err)
{
  return gpg_err_source (err);
}


/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  This function is not thread safe.  */
const char *gpgme_strerror (gpgme_error_t err);

/* Return the error string for ERR in the user-supplied buffer BUF of
   size BUFLEN.  This function is, in contrast to gpg_strerror,
   thread-safe if a thread-safe strerror_r() function is provided by
   the system.  If the function succeeds, 0 is returned and BUF
   contains the string describing the error.  If the buffer was not
   large enough, ERANGE is returned and BUF contains as much of the
   beginning of the error string as fits into the buffer.  */
int gpgme_strerror_r (gpg_error_t err, char *buf, size_t buflen);


/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *gpgme_strsource (gpgme_error_t err);


/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gpgme_err_code_t gpgme_err_code_from_errno (int err);


/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int gpgme_err_code_to_errno (gpgme_err_code_t code);

  
/* Return an error value with the error source SOURCE and the system
   error ERR.  */
gpgme_error_t gpgme_err_make_from_errno (gpgme_err_source_t source, int err);


/* Return an error value with the system error ERR.  */
gpgme_err_code_t gpgme_error_from_errno (int err);


/* The possible encoding mode of gpgme_data_t objects.  */
typedef enum
  {
    GPGME_DATA_ENCODING_NONE   = 0,	/* Not specified.  */
    GPGME_DATA_ENCODING_BINARY = 1,
    GPGME_DATA_ENCODING_BASE64 = 2,
    GPGME_DATA_ENCODING_ARMOR  = 3	/* Either PEM or OpenPGP Armor.  */
  }
gpgme_data_encoding_t;


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
gpgme_pubkey_algo_t;


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
gpgme_hash_algo_t;


/* The possible signature stati.  Deprecated, use error value in sig
   status.  */
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
_gpgme_sig_stat_t;
typedef _gpgme_sig_stat_t gpgme_sig_stat_t _GPGME_DEPRECATED;


/* The available signature modes.  */
typedef enum
  {
    GPGME_SIG_MODE_NORMAL = 0,
    GPGME_SIG_MODE_DETACH = 1,
    GPGME_SIG_MODE_CLEAR  = 2
  }
gpgme_sig_mode_t;


/* The available key and signature attributes.  Deprecated, use the
   individual result structures instead.  */
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
_gpgme_attr_t;
typedef _gpgme_attr_t gpgme_attr_t _GPGME_DEPRECATED;


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
gpgme_validity_t;


/* The available protocols.  */
typedef enum
  {
    GPGME_PROTOCOL_OpenPGP = 0,  /* The default mode.  */
    GPGME_PROTOCOL_CMS     = 1
  }
gpgme_protocol_t;


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
gpgme_status_code_t;


/* The engine information structure.  */
struct _gpgme_engine_info
{
  struct _gpgme_engine_info *next;

  /* The protocol ID.  */
  gpgme_protocol_t protocol;

  /* The file name of the engine binary.  */
  const char *file_name;

  /* The version string of the installed engine.  */
  const char *version;

  /* The minimum version required for GPGME.  */
  const char *req_version;
};
typedef struct _gpgme_engine_info *gpgme_engine_info_t;


/* A subkey from a key.  */
struct _gpgme_subkey
{
  struct _gpgme_subkey *next;

  /* True if subkey is revoked.  */
  unsigned int revoked : 1;

  /* True if subkey is expired.  */
  unsigned int expired : 1;

  /* True if subkey is disabled.  */
  unsigned int disabled : 1;

  /* True if subkey is invalid.  */
  unsigned int invalid : 1;

  /* True if subkey can be used for encryption.  */
  unsigned int can_encrypt : 1;

  /* True if subkey can be used for signing.  */
  unsigned int can_sign : 1;

  /* True if subkey can be used for certification.  */
  unsigned int can_certify : 1;

  /* True if subkey is secret.  */
  unsigned int secret : 1;

  /* True if subkey can be used for authentication.  */
  unsigned int can_authenticate : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 23;
  
  /* Public key algorithm supported by this subkey.  */
  gpgme_pubkey_algo_t pubkey_algo;

  /* Length of the subkey.  */
  unsigned int length;

  /* The key ID of the subkey.  */
  char *keyid;

  /* Internal to GPGME, do not use.  */
  char _keyid[16 + 1];

  /* The fingerprint of the subkey in hex digit form.  */
  char *fpr;

  /* The creation timestamp, -1 if invalid, 0 if not available.  */
  long int timestamp;

  /* The expiration timestamp, 0 if the subkey does not expire.  */
  long int expires;
};
typedef struct _gpgme_subkey *gpgme_subkey_t;


/* A signature on a user ID.  */
struct _gpgme_key_sig
{
  struct _gpgme_key_sig *next;

  /* True if the signature is revoked.  */
  unsigned int revoked : 1;

  /* True if the signature is expired.  */
  unsigned int expired : 1;

  /* True if the signature is invalid.  */
  unsigned int invalid : 1;

  /* True if the signature should be exported.  */
  unsigned int exportable : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 28;

  /* The public key algorithm used to create the signature.  */
  gpgme_pubkey_algo_t pubkey_algo;

  /* The key ID of key used to create the signature.  */
  char *keyid;

  /* Internal to GPGME, do not use.  */
  char _keyid[16 + 1];

  /* The creation timestamp, -1 if invalid, 0 if not available.  */
  long int timestamp;

  /* The expiration timestamp, 0 if the subkey does not expire.  */
  long int expires;

  /* Same as in gpgme_signature_t.  */
  gpgme_error_t status;

#ifdef __cplusplus
  unsigned int _obsolete_class _GPGME_DEPRECATED;
#else
  /* Must be set to SIG_CLASS below.  */
  unsigned int class _GPGME_DEPRECATED;
#endif

  /* The user ID string.  */
  char *uid;

  /* The name part of the user ID.  */
  char *name;

  /* The email part of the user ID.  */
  char *email;

  /* The comment part of the user ID.  */
  char *comment;

  /* Crypto backend specific signature class.  */
  unsigned int sig_class;
};
typedef struct _gpgme_key_sig *gpgme_key_sig_t;


/* An user ID from a key.  */
struct _gpgme_user_id
{
  struct _gpgme_user_id *next;

  /* True if the user ID is revoked.  */
  unsigned int revoked : 1;

  /* True if the user ID is invalid.  */
  unsigned int invalid : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 30;

  /* The validity of the user ID.  */
  gpgme_validity_t validity; 

  /* The user ID string.  */
  char *uid;

  /* The name part of the user ID.  */
  char *name;

  /* The email part of the user ID.  */
  char *email;

  /* The comment part of the user ID.  */
  char *comment;

  /* The signatures of the user ID.  */
  gpgme_key_sig_t signatures;

  /* Internal to GPGME, do not use.  */
  gpgme_key_sig_t _last_keysig;
};
typedef struct _gpgme_user_id *gpgme_user_id_t;


/* A key from the keyring.  */
struct _gpgme_key
{
  /* Internal to GPGME, do not use.  */
  unsigned int _refs;

  /* True if key is revoked.  */
  unsigned int revoked : 1;

  /* True if key is expired.  */
  unsigned int expired : 1;

  /* True if key is disabled.  */
  unsigned int disabled : 1;

  /* True if key is invalid.  */
  unsigned int invalid : 1;

  /* True if key can be used for encryption.  */
  unsigned int can_encrypt : 1;

  /* True if key can be used for signing.  */
  unsigned int can_sign : 1;

  /* True if key can be used for certification.  */
  unsigned int can_certify : 1;

  /* True if key is secret.  */
  unsigned int secret : 1;

  /* True if key can be used for authentication.  */
  unsigned int can_authenticate : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 23;

  /* This is the protocol supported by this key.  */
  gpgme_protocol_t protocol;

  /* If protocol is GPGME_PROTOCOL_CMS, this string contains the
     issuer serial.  */
  char *issuer_serial;

  /* If protocol is GPGME_PROTOCOL_CMS, this string contains the
     issuer name.  */
  char *issuer_name;

  /* If protocol is GPGME_PROTOCOL_CMS, this string contains the chain
     ID.  */
  char *chain_id;

  /* If protocol is GPGME_PROTOCOL_OpenPGP, this field contains the
     owner trust.  */
  gpgme_validity_t owner_trust;

  /* The subkeys of the key.  */
  gpgme_subkey_t subkeys;

  /* The user IDs of the key.  */
  gpgme_user_id_t uids;

  /* Internal to GPGME, do not use.  */
  gpgme_subkey_t _last_subkey;

  /* Internal to GPGME, do not use.  */
  gpgme_user_id_t _last_uid;
};
typedef struct _gpgme_key *gpgme_key_t;



/* Types for callback functions.  */

/* Request a passphrase from the user.  */
typedef gpgme_error_t (*gpgme_passphrase_cb_t) (void *hook,
						const char *uid_hint,
						const char *passphrase_info,
						int prev_was_bad, int fd);

/* Inform the user about progress made.  */
typedef void (*gpgme_progress_cb_t) (void *opaque, const char *what,
				     int type, int current, int total);

/* Interact with the user about an edit operation.  */
typedef gpgme_error_t (*gpgme_edit_cb_t) (void *opaque,
					  gpgme_status_code_t status,
					  const char *args, int fd);


/* Context management functions.  */

/* Create a new context and return it in CTX.  */
gpgme_error_t gpgme_new (gpgme_ctx_t *ctx);

/* Release the context CTX.  */
void gpgme_release (gpgme_ctx_t ctx);

/* Set the protocol to be used by CTX to PROTO.  */
gpgme_error_t gpgme_set_protocol (gpgme_ctx_t ctx, gpgme_protocol_t proto);

/* Get the protocol used with CTX */
gpgme_protocol_t gpgme_get_protocol (gpgme_ctx_t ctx);

/* Get the string describing protocol PROTO, or NULL if invalid.  */
const char *gpgme_get_protocol_name (gpgme_protocol_t proto);

/* If YES is non-zero, enable armor mode in CTX, disable it otherwise.  */
void gpgme_set_armor (gpgme_ctx_t ctx, int yes);

/* Return non-zero if armor mode is set in CTX.  */
int gpgme_get_armor (gpgme_ctx_t ctx);

/* If YES is non-zero, enable text mode in CTX, disable it otherwise.  */
void gpgme_set_textmode (gpgme_ctx_t ctx, int yes);

/* Return non-zero if text mode is set in CTX.  */
int gpgme_get_textmode (gpgme_ctx_t ctx);

/* Include up to NR_OF_CERTS certificates in an S/MIME message.  */
void gpgme_set_include_certs (gpgme_ctx_t ctx, int nr_of_certs);

/* Return the number of certs to include in an S/MIME message.  */
int gpgme_get_include_certs (gpgme_ctx_t ctx);

/* The available keylist mode flags.  */
typedef enum
  {
    GPGME_KEYLIST_MODE_LOCAL  = 1,
    GPGME_KEYLIST_MODE_EXTERN = 2,
    GPGME_KEYLIST_MODE_SIGS   = 4
  }
gpgme_keylist_mode_t;

/* Set keylist mode in CTX to MODE.  */
gpgme_error_t gpgme_set_keylist_mode (gpgme_ctx_t ctx,
				      gpgme_keylist_mode_t mode);

/* Get keylist mode in CTX.  */
gpgme_keylist_mode_t gpgme_get_keylist_mode (gpgme_ctx_t ctx);

/* Set the passphrase callback function in CTX to CB.  HOOK_VALUE is
   passed as first argument to the passphrase callback function.  */
void gpgme_set_passphrase_cb (gpgme_ctx_t ctx,
                              gpgme_passphrase_cb_t cb, void *hook_value);

/* Get the current passphrase callback function in *CB and the current
   hook value in *HOOK_VALUE.  */
void gpgme_get_passphrase_cb (gpgme_ctx_t ctx, gpgme_passphrase_cb_t *cb,
			      void **hook_value);

/* Set the progress callback function in CTX to CB.  HOOK_VALUE is
   passed as first argument to the progress callback function.  */
void gpgme_set_progress_cb (gpgme_ctx_t c, gpgme_progress_cb_t cb,
			    void *hook_value);

/* Get the current progress callback function in *CB and the current
   hook value in *HOOK_VALUE.  */
void gpgme_get_progress_cb (gpgme_ctx_t ctx, gpgme_progress_cb_t *cb,
			    void **hook_value);

/* This function sets the locale for the context CTX, or the default
   locale if CTX is a null pointer.  */
gpgme_error_t gpgme_set_locale (gpgme_ctx_t ctx, int category,
				const char *value);

/* Return a statically allocated string with the name of the public
   key algorithm ALGO, or NULL if that name is not known.  */
const char *gpgme_pubkey_algo_name (gpgme_pubkey_algo_t algo);

/* Return a statically allocated string with the name of the hash
   algorithm ALGO, or NULL if that name is not known.  */
const char *gpgme_hash_algo_name (gpgme_hash_algo_t algo);


/* Delete all signers from CTX.  */
void gpgme_signers_clear (gpgme_ctx_t ctx);

/* Add KEY to list of signers in CTX.  */
gpgme_error_t gpgme_signers_add (gpgme_ctx_t ctx, const gpgme_key_t key);

/* Return the SEQth signer's key in CTX.  */
gpgme_key_t gpgme_signers_enum (const gpgme_ctx_t ctx, int seq);

/* Retrieve the signature status of signature IDX in CTX after a
   successful verify operation in R_STAT (if non-null).  The creation
   time stamp of the signature is returned in R_CREATED (if non-null).
   The function returns a string containing the fingerprint.
   Deprecated, use verify result directly.  */
const char *gpgme_get_sig_status (gpgme_ctx_t ctx, int idx,
                                  _gpgme_sig_stat_t *r_stat,
				  time_t *r_created) _GPGME_DEPRECATED;

/* Retrieve certain attributes of a signature.  IDX is the index
   number of the signature after a successful verify operation.  WHAT
   is an attribute where GPGME_ATTR_EXPIRE is probably the most useful
   one.  WHATIDX is to be passed as 0 for most attributes . */
unsigned long gpgme_get_sig_ulong_attr (gpgme_ctx_t c, int idx,
                                        _gpgme_attr_t what, int whatidx)
     _GPGME_DEPRECATED;
const char *gpgme_get_sig_string_attr (gpgme_ctx_t c, int idx,
				       _gpgme_attr_t what, int whatidx)
     _GPGME_DEPRECATED;


/* Get the key used to create signature IDX in CTX and return it in
   R_KEY.  */
gpgme_error_t gpgme_get_sig_key (gpgme_ctx_t ctx, int idx, gpgme_key_t *r_key)
     _GPGME_DEPRECATED;


/* Run control.  */

/* The type of an I/O callback function.  */
typedef gpgme_error_t (*gpgme_io_cb_t) (void *data, int fd);

/* The type of a function that can register FNC as the I/O callback
   function for the file descriptor FD with direction dir (0: for writing,
   1: for reading).  FNC_DATA should be passed as DATA to FNC.  The
   function should return a TAG suitable for the corresponding
   gpgme_remove_io_cb_t, and an error value.  */
typedef gpgme_error_t (*gpgme_register_io_cb_t) (void *data, int fd, int dir,
						 gpgme_io_cb_t fnc,
						 void *fnc_data, void **tag);

/* The type of a function that can remove a previously registered I/O
   callback function given TAG as returned by the register
   function.  */
typedef void (*gpgme_remove_io_cb_t) (void *tag);

typedef enum
  {
    GPGME_EVENT_START,
    GPGME_EVENT_DONE,
    GPGME_EVENT_NEXT_KEY,
    GPGME_EVENT_NEXT_TRUSTITEM
  }
gpgme_event_io_t;

/* The type of a function that is called when a context finished an
   operation.  */
typedef void (*gpgme_event_io_cb_t) (void *data, gpgme_event_io_t type,
				     void *type_data);

struct gpgme_io_cbs
{
  gpgme_register_io_cb_t add;
  void *add_priv;
  gpgme_remove_io_cb_t remove;
  gpgme_event_io_cb_t event;
  void *event_priv;
};
typedef struct gpgme_io_cbs *gpgme_io_cbs_t;

/* Set the I/O callback functions in CTX to IO_CBS.  */
void gpgme_set_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs);

/* Get the current I/O callback functions.  */
void gpgme_get_io_cbs (gpgme_ctx_t ctx, gpgme_io_cbs_t io_cbs);

/* Process the pending operation and, if HANG is non-zero, wait for
   the pending operation to finish.  */
gpgme_ctx_t gpgme_wait (gpgme_ctx_t ctx, gpgme_error_t *status, int hang);


/* Functions to handle data objects.  */

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle HANDLE.  Return the number of characters read, 0 on EOF
   and -1 on error.  If an error occurs, errno is set.  */
typedef ssize_t (*gpgme_data_read_cb_t) (void *handle, void *buffer,
					 size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle HANDLE.  Return the number of characters written, or -1
   on error.  If an error occurs, errno is set.  */
typedef ssize_t (*gpgme_data_write_cb_t) (void *handle, const void *buffer,
					  size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle HANDLE to OFFSET, relativ to
   WHENCE.  */
typedef off_t (*gpgme_data_seek_cb_t) (void *handle, off_t offset, int whence);

/* Close the data object with the handle DL.  */
typedef void (*gpgme_data_release_cb_t) (void *handle);

struct gpgme_data_cbs
{
  gpgme_data_read_cb_t read;
  gpgme_data_write_cb_t write;
  gpgme_data_seek_cb_t seek;
  gpgme_data_release_cb_t release;
};
typedef struct gpgme_data_cbs *gpgme_data_cbs_t;

/* Read up to SIZE bytes into buffer BUFFER from the data object with
   the handle DH.  Return the number of characters read, 0 on EOF and
   -1 on error.  If an error occurs, errno is set.  */
ssize_t gpgme_data_read (gpgme_data_t dh, void *buffer, size_t size);

/* Write up to SIZE bytes from buffer BUFFER to the data object with
   the handle DH.  Return the number of characters written, or -1 on
   error.  If an error occurs, errno is set.  */
ssize_t gpgme_data_write (gpgme_data_t dh, const void *buffer, size_t size);

/* Set the current position from where the next read or write starts
   in the data object with the handle DH to OFFSET, relativ to
   WHENCE.  */
off_t gpgme_data_seek (gpgme_data_t dh, off_t offset, int whence);

/* Create a new data buffer and return it in R_DH.  */
gpgme_error_t gpgme_data_new (gpgme_data_t *r_dh);

/* Destroy the data buffer DH.  */
void gpgme_data_release (gpgme_data_t dh);

/* Create a new data buffer filled with SIZE bytes starting from
   BUFFER.  If COPY is zero, copying is delayed until necessary, and
   the data is taken from the original location when needed.  */
gpgme_error_t gpgme_data_new_from_mem (gpgme_data_t *r_dh,
				       const char *buffer, size_t size,
				       int copy);

/* Destroy the data buffer DH and return a pointer to its content.
   The memory has be to released with free by the user.  It's size is
   returned in R_LEN.  */
char *gpgme_data_release_and_get_mem (gpgme_data_t dh, size_t *r_len);

gpgme_error_t gpgme_data_new_from_cbs (gpgme_data_t *dh,
				       gpgme_data_cbs_t cbs,
				       void *handle);

gpgme_error_t gpgme_data_new_from_fd (gpgme_data_t *dh, int fd);

gpgme_error_t gpgme_data_new_from_stream (gpgme_data_t *dh, FILE *stream);

/* Return the encoding attribute of the data buffer DH */
gpgme_data_encoding_t gpgme_data_get_encoding (gpgme_data_t dh);

/* Set the encoding attribute of data buffer DH to ENC */
gpgme_error_t gpgme_data_set_encoding (gpgme_data_t dh,
				       gpgme_data_encoding_t enc);



/* Create a new data buffer which retrieves the data from the callback
   function READ_CB.  Deprecated, please use gpgme_data_new_from_cbs
   instead.  */
gpgme_error_t gpgme_data_new_with_read_cb (gpgme_data_t *r_dh,
					   int (*read_cb) (void*,char *,
							   size_t,size_t*),
					   void *read_cb_value)
     _GPGME_DEPRECATED;

/* Create a new data buffer filled with the content of file FNAME.
   COPY must be non-zero.  For delayed read, please use
   gpgme_data_new_from_fd or gpgme_data_new_from stream instead.  */
gpgme_error_t gpgme_data_new_from_file (gpgme_data_t *r_dh,
					const char *fname,
					int copy);

/* Create a new data buffer filled with LENGTH bytes starting from
   OFFSET within the file FNAME or stream FP (exactly one must be
   non-zero).  */
gpgme_error_t gpgme_data_new_from_filepart (gpgme_data_t *r_dh,
					    const char *fname, FILE *fp,
					    off_t offset, size_t length);

/* Reset the read pointer in DH.  Deprecated, please use
   gpgme_data_seek instead.  */
gpgme_error_t gpgme_data_rewind (gpgme_data_t dh) _GPGME_DEPRECATED;


/* Key and trust functions.  */

/* Get the key with the fingerprint FPR from the crypto backend.  If
   SECRET is true, get the secret key.  */
gpgme_error_t gpgme_get_key (gpgme_ctx_t ctx, const char *fpr,
			     gpgme_key_t *r_key, int secret);

/* Acquire a reference to KEY.  */
void gpgme_key_ref (gpgme_key_t key);

/* Release a reference to KEY.  If this was the last one the key is
   destroyed.  */
void gpgme_key_unref (gpgme_key_t key);
void gpgme_key_release (gpgme_key_t key);

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by a string.  IDX specifies the sub key or user ID
   for attributes related to sub keys or user IDs.  Deprecated, use
   key structure directly instead. */
const char *gpgme_key_get_string_attr (gpgme_key_t key, _gpgme_attr_t what,
				       const void *reserved, int idx)
     _GPGME_DEPRECATED;

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an unsigned integer.  IDX specifies the sub key or
   user ID for attributes related to sub keys or user IDs.
   Deprecated, use key structure directly instead.  */
unsigned long gpgme_key_get_ulong_attr (gpgme_key_t key, _gpgme_attr_t what,
					const void *reserved, int idx)
     _GPGME_DEPRECATED;

/* Return the value of the attribute WHAT of a signature on user ID
   UID_IDX in KEY, which has to be representable by a string.  IDX
   specifies the signature.  Deprecated, use key structure directly
   instead.  */
const char *gpgme_key_sig_get_string_attr (gpgme_key_t key, int uid_idx,
					   _gpgme_attr_t what,
					   const void *reserved, int idx)
     _GPGME_DEPRECATED;

/* Return the value of the attribute WHAT of a signature on user ID
   UID_IDX in KEY, which has to be representable by an unsigned
   integer string.  IDX specifies the signature.  Deprecated, use key
   structure directly instead.  */
unsigned long gpgme_key_sig_get_ulong_attr (gpgme_key_t key, int uid_idx,
					    _gpgme_attr_t what,
					    const void *reserved, int idx)
     _GPGME_DEPRECATED;


/* Crypto Operations.  */

struct _gpgme_invalid_key
{
  struct _gpgme_invalid_key *next;
  char *fpr;
  gpgme_error_t reason;
};
typedef struct _gpgme_invalid_key *gpgme_invalid_key_t;


/* Encryption.  */
struct _gpgme_op_encrypt_result
{
  /* The list of invalid recipients.  */
  gpgme_invalid_key_t invalid_recipients;
};
typedef struct _gpgme_op_encrypt_result *gpgme_encrypt_result_t;

/* Retrieve a pointer to the result of the encrypt operation.  */
gpgme_encrypt_result_t gpgme_op_encrypt_result (gpgme_ctx_t ctx);

/* The valid encryption flags.  */
typedef enum
  {
    GPGME_ENCRYPT_ALWAYS_TRUST = 1
  }
gpgme_encrypt_flags_t;

/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
   store the resulting ciphertext in CIPHER.  */
gpgme_error_t gpgme_op_encrypt_start (gpgme_ctx_t ctx, gpgme_key_t recp[],
				      gpgme_encrypt_flags_t flags,
				      gpgme_data_t plain, gpgme_data_t cipher);
gpgme_error_t gpgme_op_encrypt (gpgme_ctx_t ctx, gpgme_key_t recp[],
				gpgme_encrypt_flags_t flags,
				gpgme_data_t plain, gpgme_data_t cipher);

/* Encrypt plaintext PLAIN within CTX for the recipients RECP and
   store the resulting ciphertext in CIPHER.  Also sign the ciphertext
   with the signers in CTX.  */
gpgme_error_t gpgme_op_encrypt_sign_start (gpgme_ctx_t ctx,
					   gpgme_key_t recp[],
					   gpgme_encrypt_flags_t flags,
					   gpgme_data_t plain,
					   gpgme_data_t cipher);
gpgme_error_t gpgme_op_encrypt_sign (gpgme_ctx_t ctx, gpgme_key_t recp[],
				     gpgme_encrypt_flags_t flags,
				     gpgme_data_t plain, gpgme_data_t cipher);


/* Decryption.  */
struct _gpgme_op_decrypt_result
{
  char *unsupported_algorithm;
};
typedef struct _gpgme_op_decrypt_result *gpgme_decrypt_result_t;

/* Retrieve a pointer to the result of the decrypt operation.  */
gpgme_decrypt_result_t gpgme_op_decrypt_result (gpgme_ctx_t ctx);

/* Decrypt ciphertext CIPHER within CTX and store the resulting
   plaintext in PLAIN.  */
gpgme_error_t gpgme_op_decrypt_start (gpgme_ctx_t ctx, gpgme_data_t cipher,
				      gpgme_data_t plain);
gpgme_error_t gpgme_op_decrypt (gpgme_ctx_t ctx,
				gpgme_data_t cipher, gpgme_data_t plain);

/* Decrypt ciphertext CIPHER and make a signature verification within
   CTX and store the resulting plaintext in PLAIN.  */
gpgme_error_t gpgme_op_decrypt_verify_start (gpgme_ctx_t ctx,
					     gpgme_data_t cipher,
					     gpgme_data_t plain);
gpgme_error_t gpgme_op_decrypt_verify (gpgme_ctx_t ctx, gpgme_data_t cipher,
				       gpgme_data_t plain);


/* Signing.  */
struct _gpgme_new_signature
{
  struct _gpgme_new_signature *next;

  /* The type of the signature.  */
  gpgme_sig_mode_t type;

  /* The public key algorithm used to create the signature.  */
  gpgme_pubkey_algo_t pubkey_algo;

  /* The hash algorithm used to create the signature.  */
  gpgme_hash_algo_t hash_algo;

  /* Internal to GPGME, do not use.  Must be set to the same value as
     CLASS below.  */
  unsigned long _obsolete_class;

  /* Signature creation time.  */
  long int timestamp;

  /* The fingerprint of the signature.  */
  char *fpr;

#ifdef __cplusplus
  unsigned int _obsolete_class_2;
#else
  /* Must be set to SIG_CLASS below.  */
  unsigned int class _GPGME_DEPRECATED;
#endif

  /* Crypto backend specific signature class.  */
  unsigned int sig_class;
};
typedef struct _gpgme_new_signature *gpgme_new_signature_t;

struct _gpgme_op_sign_result
{
  /* The list of invalid signers.  */
  gpgme_invalid_key_t invalid_signers;
  gpgme_new_signature_t signatures;
};
typedef struct _gpgme_op_sign_result *gpgme_sign_result_t;

/* Retrieve a pointer to the result of the signing operation.  */
gpgme_sign_result_t gpgme_op_sign_result (gpgme_ctx_t ctx);

/* Sign the plaintext PLAIN and store the signature in SIG.  */
gpgme_error_t gpgme_op_sign_start (gpgme_ctx_t ctx,
				   gpgme_data_t plain, gpgme_data_t sig,
				   gpgme_sig_mode_t mode);
gpgme_error_t gpgme_op_sign (gpgme_ctx_t ctx,
			     gpgme_data_t plain, gpgme_data_t sig,
			     gpgme_sig_mode_t mode);


/* Verify.  */
struct _gpgme_sig_notation
{
  struct _gpgme_sig_notation *next;

  /* If NAME is a null pointer, then VALUE contains a policy URL
     rather than a notation.  */
  char *name;
  char *value;
};
typedef struct _gpgme_sig_notation *gpgme_sig_notation_t;

/* Flags used for the SUMMARY field in a gpgme_signature_t.  */
typedef enum
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
  }
gpgme_sigsum_t;

struct _gpgme_signature
{
  struct _gpgme_signature *next;

  /* A summary of the signature status.  */
  gpgme_sigsum_t summary;

  /* The fingerprint or key ID of the signature.  */
  char *fpr;

  /* The status of the signature.  */
  gpgme_error_t status;

  /* Notation data and policy URLs.  */
  gpgme_sig_notation_t notations;

  /* Signature creation time.  */
  unsigned long timestamp;

  /* Signature exipration time or 0.  */
  unsigned long exp_timestamp;

  int wrong_key_usage : 1;

  /* Internal to GPGME, do not use.  */
  int _unused : 31;

  gpgme_validity_t validity;
  gpgme_error_t validity_reason;
};
typedef struct _gpgme_signature *gpgme_signature_t;

struct _gpgme_op_verify_result
{
  gpgme_signature_t signatures;
};
typedef struct _gpgme_op_verify_result *gpgme_verify_result_t;

/* Retrieve a pointer to the result of the verify operation.  */
gpgme_verify_result_t gpgme_op_verify_result (gpgme_ctx_t ctx);

/* Verify within CTX that SIG is a valid signature for TEXT.  */
gpgme_error_t gpgme_op_verify_start (gpgme_ctx_t ctx, gpgme_data_t sig,
				     gpgme_data_t signed_text,
				     gpgme_data_t plaintext);
gpgme_error_t gpgme_op_verify (gpgme_ctx_t ctx, gpgme_data_t sig,
			       gpgme_data_t signed_text,
			       gpgme_data_t plaintext);


/* Import.  */
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
  gpgme_error_t result;

  /* The result of the import, the GPGME_IMPORT_* values bit-wise
     ORed.  0 means the key was already known and no new components
     have been added.  */
  unsigned int status;
};
typedef struct _gpgme_import_status *gpgme_import_status_t;

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

  /* Number of new keys skipped.  */
  int skipped_new_keys;

  /* Number of keys not imported.  */
  int not_imported;

  /* List of keys for which an import was attempted.  */
  gpgme_import_status_t imports;
};
typedef struct _gpgme_op_import_result *gpgme_import_result_t;

/* Retrieve a pointer to the result of the import operation.  */
gpgme_import_result_t gpgme_op_import_result (gpgme_ctx_t ctx);

/* Import the key in KEYDATA into the keyring.  */
gpgme_error_t gpgme_op_import_start (gpgme_ctx_t ctx, gpgme_data_t keydata);
gpgme_error_t gpgme_op_import (gpgme_ctx_t ctx, gpgme_data_t keydata);
gpgme_error_t gpgme_op_import_ext (gpgme_ctx_t ctx, gpgme_data_t keydata,
				   int *nr) _GPGME_DEPRECATED;


/* Export the keys found by PATTERN into KEYDATA.  */
gpgme_error_t gpgme_op_export_start (gpgme_ctx_t ctx, const char *pattern,
				     unsigned int reserved,
				     gpgme_data_t keydata);
gpgme_error_t gpgme_op_export (gpgme_ctx_t ctx, const char *pattern,
			       unsigned int reserved, gpgme_data_t keydata);

gpgme_error_t gpgme_op_export_ext_start (gpgme_ctx_t ctx,
					 const char *pattern[],
					 unsigned int reserved,
					 gpgme_data_t keydata);
gpgme_error_t gpgme_op_export_ext (gpgme_ctx_t ctx, const char *pattern[],
				   unsigned int reserved,
				   gpgme_data_t keydata);


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
typedef struct _gpgme_op_genkey_result *gpgme_genkey_result_t;

/* Generate a new keypair and add it to the keyring.  PUBKEY and
   SECKEY should be null for now.  PARMS specifies what keys should be
   generated.  */
gpgme_error_t gpgme_op_genkey_start (gpgme_ctx_t ctx, const char *parms,
				     gpgme_data_t pubkey, gpgme_data_t seckey);
gpgme_error_t gpgme_op_genkey (gpgme_ctx_t ctx, const char *parms,
			       gpgme_data_t pubkey, gpgme_data_t seckey);

/* Retrieve a pointer to the result of the genkey operation.  */
gpgme_genkey_result_t gpgme_op_genkey_result (gpgme_ctx_t ctx);


/* Delete KEY from the keyring.  If ALLOW_SECRET is non-zero, secret
   keys are also deleted.  */
gpgme_error_t gpgme_op_delete_start (gpgme_ctx_t ctx, const gpgme_key_t key,
				     int allow_secret);
gpgme_error_t gpgme_op_delete (gpgme_ctx_t ctx, const gpgme_key_t key,
			       int allow_secret);


/* Edit the key KEY.  Send status and command requests to FNC and
   output of edit commands to OUT.  */
gpgme_error_t gpgme_op_edit_start (gpgme_ctx_t ctx, gpgme_key_t key,
				   gpgme_edit_cb_t fnc, void *fnc_value,
				   gpgme_data_t out);
gpgme_error_t gpgme_op_edit (gpgme_ctx_t ctx, gpgme_key_t key,
			     gpgme_edit_cb_t fnc, void *fnc_value,
			     gpgme_data_t out);

/* Edit the card for the key KEY.  Send status and command requests to
   FNC and output of edit commands to OUT.  */
gpgme_error_t gpgme_op_card_edit_start (gpgme_ctx_t ctx, gpgme_key_t key,
					gpgme_edit_cb_t fnc, void *fnc_value,
					gpgme_data_t out);
gpgme_error_t gpgme_op_card_edit (gpgme_ctx_t ctx, gpgme_key_t key,
				  gpgme_edit_cb_t fnc, void *fnc_value,
				  gpgme_data_t out);


/* Key management functions.  */
struct _gpgme_op_keylist_result
{
  unsigned int truncated : 1;

  /* Internal to GPGME, do not use.  */
  unsigned int _unused : 31;
};
typedef struct _gpgme_op_keylist_result *gpgme_keylist_result_t;

/* Retrieve a pointer to the result of the key listing operation.  */
gpgme_keylist_result_t gpgme_op_keylist_result (gpgme_ctx_t ctx);

/* Start a keylist operation within CTX, searching for keys which
   match PATTERN.  If SECRET_ONLY is true, only secret keys are
   returned.  */
gpgme_error_t gpgme_op_keylist_start (gpgme_ctx_t ctx, const char *pattern,
				      int secret_only);
gpgme_error_t gpgme_op_keylist_ext_start (gpgme_ctx_t ctx,
					  const char *pattern[],
					  int secret_only, int reserved);

/* Return the next key from the keylist in R_KEY.  */
gpgme_error_t gpgme_op_keylist_next (gpgme_ctx_t ctx, gpgme_key_t *r_key);

/* Terminate a pending keylist operation within CTX.  */
gpgme_error_t gpgme_op_keylist_end (gpgme_ctx_t ctx);


/* Trust items and operations.  */

struct _gpgme_trust_item
{
  /* Internal to GPGME, do not use.  */
  unsigned int _refs;

  /* The key ID to which the trust item belongs.  */
  char *keyid;

  /* Internal to GPGME, do not use.  */
  char _keyid[16 + 1];

  /* The type of the trust item, 1 refers to a key, 2 to a user ID.  */
  int type;

  /* The trust level.  */
  int level;

  /* The owner trust if TYPE is 1.  */
  char *owner_trust;

  /* Internal to GPGME, do not use.  */
  char _owner_trust[2];

  /* The calculated validity.  */
  char *validity;
 
  /* Internal to GPGME, do not use.  */
  char _validity[2];

  /* The user name if TYPE is 2.  */
  char *name;
};
typedef struct _gpgme_trust_item *gpgme_trust_item_t;

/* Start a trustlist operation within CTX, searching for trust items
   which match PATTERN.  */
gpgme_error_t gpgme_op_trustlist_start (gpgme_ctx_t ctx,
					const char *pattern, int max_level);

/* Return the next trust item from the trustlist in R_ITEM.  */
gpgme_error_t gpgme_op_trustlist_next (gpgme_ctx_t ctx,
				       gpgme_trust_item_t *r_item);

/* Terminate a pending trustlist operation within CTX.  */
gpgme_error_t gpgme_op_trustlist_end (gpgme_ctx_t ctx);

/* Acquire a reference to ITEM.  */
void gpgme_trust_item_ref (gpgme_trust_item_t item);

/* Release a reference to ITEM.  If this was the last one the trust
   item is destroyed.  */
void gpgme_trust_item_unref (gpgme_trust_item_t item);

/* Release the trust item ITEM.  Deprecated, use
   gpgme_trust_item_unref.  */
void gpgme_trust_item_release (gpgme_trust_item_t item) _GPGME_DEPRECATED;

/* Return the value of the attribute WHAT of ITEM, which has to be
   representable by a string.  Deprecated, use trust item structure
   directly.  */
const char *gpgme_trust_item_get_string_attr (gpgme_trust_item_t item,
					      _gpgme_attr_t what,
					      const void *reserved, int idx)
     _GPGME_DEPRECATED;

/* Return the value of the attribute WHAT of KEY, which has to be
   representable by an integer.  IDX specifies a running index if the
   attribute appears more than once in the key.  Deprecated, use trust
   item structure directly.  */
int gpgme_trust_item_get_int_attr (gpgme_trust_item_t item, _gpgme_attr_t what,
				   const void *reserved, int idx)
     _GPGME_DEPRECATED;


/* Various functions.  */

/* Check that the library fulfills the version requirement.  */
const char *gpgme_check_version (const char *req_version);

/* Retrieve information about the backend engines.  */
gpgme_error_t gpgme_get_engine_info (gpgme_engine_info_t *engine_info);


/* Engine support functions.  */

/* Verify that the engine implementing PROTO is installed and
   available.  */
gpgme_error_t gpgme_engine_check_version (gpgme_protocol_t proto);


/* Deprecated types.  */
typedef gpgme_ctx_t GpgmeCtx _GPGME_DEPRECATED;
typedef gpgme_data_t GpgmeData _GPGME_DEPRECATED;
typedef gpgme_error_t GpgmeError _GPGME_DEPRECATED;
typedef gpgme_data_encoding_t GpgmeDataEncoding _GPGME_DEPRECATED;
typedef gpgme_pubkey_algo_t GpgmePubKeyAlgo _GPGME_DEPRECATED;
typedef gpgme_hash_algo_t GpgmeHashAlgo _GPGME_DEPRECATED;
typedef gpgme_sig_stat_t GpgmeSigStat _GPGME_DEPRECATED;
typedef gpgme_sig_mode_t GpgmeSigMode _GPGME_DEPRECATED;
typedef gpgme_attr_t GpgmeAttr _GPGME_DEPRECATED;
typedef gpgme_validity_t GpgmeValidity _GPGME_DEPRECATED;
typedef gpgme_protocol_t GpgmeProtocol _GPGME_DEPRECATED;
typedef gpgme_engine_info_t GpgmeEngineInfo _GPGME_DEPRECATED;
typedef gpgme_subkey_t GpgmeSubkey _GPGME_DEPRECATED;
typedef gpgme_key_sig_t GpgmeKeySig _GPGME_DEPRECATED;
typedef gpgme_user_id_t GpgmeUserID _GPGME_DEPRECATED;
typedef gpgme_key_t GpgmeKey _GPGME_DEPRECATED;
typedef gpgme_passphrase_cb_t GpgmePassphraseCb _GPGME_DEPRECATED;
typedef gpgme_progress_cb_t GpgmeProgressCb _GPGME_DEPRECATED;
typedef gpgme_io_cb_t GpgmeIOCb _GPGME_DEPRECATED;
typedef gpgme_register_io_cb_t GpgmeRegisterIOCb _GPGME_DEPRECATED;
typedef gpgme_remove_io_cb_t GpgmeRemoveIOCb _GPGME_DEPRECATED;
typedef gpgme_event_io_t GpgmeEventIO _GPGME_DEPRECATED;
typedef gpgme_event_io_cb_t GpgmeEventIOCb _GPGME_DEPRECATED;
#define GpgmeIOCbs gpgme_io_cbs
typedef gpgme_data_read_cb_t GpgmeDataReadCb _GPGME_DEPRECATED;
typedef gpgme_data_write_cb_t GpgmeDataWriteCb _GPGME_DEPRECATED;
typedef gpgme_data_seek_cb_t GpgmeDataSeekCb _GPGME_DEPRECATED;
typedef gpgme_data_release_cb_t GpgmeDataReleaseCb _GPGME_DEPRECATED;
#define GpgmeDataCbs gpgme_data_cbs
typedef gpgme_encrypt_result_t GpgmeEncryptResult _GPGME_DEPRECATED;
typedef gpgme_sig_notation_t GpgmeSigNotation _GPGME_DEPRECATED;
typedef	gpgme_signature_t GpgmeSignature _GPGME_DEPRECATED;
typedef gpgme_verify_result_t GpgmeVerifyResult _GPGME_DEPRECATED;
typedef gpgme_import_status_t GpgmeImportStatus _GPGME_DEPRECATED;
typedef gpgme_import_result_t GpgmeImportResult _GPGME_DEPRECATED;
typedef gpgme_genkey_result_t GpgmeGenKeyResult _GPGME_DEPRECATED;
typedef	gpgme_trust_item_t GpgmeTrustItem _GPGME_DEPRECATED;
typedef gpgme_status_code_t GpgmeStatusCode _GPGME_DEPRECATED;

#ifdef __cplusplus
}
#endif
#endif /* GPGME_H */

#define GPGMEPLUG_PROTOCOL GPGME_PROTOCOL_OpenPGP

/* definitions for signing */
// 1. opaque signatures (only used for S/MIME)
#define GPGMEPLUG_OPA_SIGN_INCLUDE_CLEARTEXT false
#define GPGMEPLUG_OPA_SIGN_MAKE_MIME_OBJECT  false
#define GPGMEPLUG_OPA_SIGN_MAKE_MULTI_MIME   false
#define GPGMEPLUG_OPA_SIGN_CTYPE_MAIN        ""
#define GPGMEPLUG_OPA_SIGN_CDISP_MAIN        ""
#define GPGMEPLUG_OPA_SIGN_CTENC_MAIN        ""
#define GPGMEPLUG_OPA_SIGN_CTYPE_VERSION     ""
#define GPGMEPLUG_OPA_SIGN_CDISP_VERSION     ""
#define GPGMEPLUG_OPA_SIGN_CTENC_VERSION     ""
#define GPGMEPLUG_OPA_SIGN_BTEXT_VERSION     ""
#define GPGMEPLUG_OPA_SIGN_CTYPE_CODE        ""
#define GPGMEPLUG_OPA_SIGN_CDISP_CODE        ""
#define GPGMEPLUG_OPA_SIGN_CTENC_CODE        ""
#define GPGMEPLUG_OPA_SIGN_FLAT_PREFIX       ""
#define GPGMEPLUG_OPA_SIGN_FLAT_SEPARATOR    ""
#define GPGMEPLUG_OPA_SIGN_FLAT_POSTFIX      ""
// 2. detached signatures (used for S/MIME and for OpenPGP)
#define GPGMEPLUG_DET_SIGN_INCLUDE_CLEARTEXT true
#define GPGMEPLUG_DET_SIGN_MAKE_MIME_OBJECT  true
#define GPGMEPLUG_DET_SIGN_MAKE_MULTI_MIME   true
#define GPGMEPLUG_DET_SIGN_CTYPE_MAIN        "multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha1"
#define GPGMEPLUG_DET_SIGN_CDISP_MAIN        ""
#define GPGMEPLUG_DET_SIGN_CTENC_MAIN        ""
#define GPGMEPLUG_DET_SIGN_CTYPE_VERSION     ""
#define GPGMEPLUG_DET_SIGN_CDISP_VERSION     ""
#define GPGMEPLUG_DET_SIGN_CTENC_VERSION     ""
#define GPGMEPLUG_DET_SIGN_BTEXT_VERSION     ""
#define GPGMEPLUG_DET_SIGN_CTYPE_CODE        "application/pgp-signature"
#define GPGMEPLUG_DET_SIGN_CDISP_CODE        ""
#define GPGMEPLUG_DET_SIGN_CTENC_CODE        ""
#define GPGMEPLUG_DET_SIGN_FLAT_PREFIX       ""
#define GPGMEPLUG_DET_SIGN_FLAT_SEPARATOR    ""
#define GPGMEPLUG_DET_SIGN_FLAT_POSTFIX      ""
// 3. common definitions for opaque and detached signing
#define __GPGMEPLUG_SIGNATURE_CODE_IS_BINARY false

/* definitions for encoding */
#define GPGMEPLUG_ENC_INCLUDE_CLEARTEXT  false
#define GPGMEPLUG_ENC_MAKE_MIME_OBJECT   true
#define GPGMEPLUG_ENC_MAKE_MULTI_MIME    true
#define GPGMEPLUG_ENC_CTYPE_MAIN         "multipart/encrypted; protocol=\"application/pgp-encrypted\""
#define GPGMEPLUG_ENC_CDISP_MAIN         ""
#define GPGMEPLUG_ENC_CTENC_MAIN         ""
#define GPGMEPLUG_ENC_CTYPE_VERSION      "application/pgp-encrypted"
#define GPGMEPLUG_ENC_CDISP_VERSION      "attachment"
#define GPGMEPLUG_ENC_CTENC_VERSION      ""
#define GPGMEPLUG_ENC_BTEXT_VERSION      "Version: 1"
#define GPGMEPLUG_ENC_CTYPE_CODE         "application/octet-stream"
#define GPGMEPLUG_ENC_CDISP_CODE         "inline; filename=\"msg.asc\""
#define GPGMEPLUG_ENC_CTENC_CODE         ""
#define GPGMEPLUG_ENC_FLAT_PREFIX        ""
#define GPGMEPLUG_ENC_FLAT_SEPARATOR     ""
#define GPGMEPLUG_ENC_FLAT_POSTFIX       ""
#define __GPGMEPLUG_ENCRYPTED_CODE_IS_BINARY false

#include "gpgmeplug.c"

/* -*- Mode: C -*-

  $Id$

  GPGMEPLUG - an GPGME based cryptography plug-in following
              the common CRYPTPLUG specification.

  Copyright (C) 2001 by Klarälvdalens Datakonsult AB

  GPGMEPLUG is free software; you can redistribute it and/or modify
  it under the terms of GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  GPGMEPLUG is distributed in the hope that it will be useful,
  it under the terms of GNU General Public License as published by
  the Free Software Foundation; version 2 of the License
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/



/*! \file gpgmeplug.c
    \brief GPGME implementation of CRYPTPLUG following the
    specification located in common API header cryptplug.h.

    CRYPTPLUG is an independent cryptography plug-in API
    developed for Sphinx-enabeling KMail and Mutt.

    CRYPTPLUG was designed for the Aegypten project, but it may
    be used by 3rd party developers as well to design pluggable
    crypto backends for the above mentioned MUAs.

    \note All string parameters appearing in this API are to be
    interpreted as UTF-8 encoded.

    \see cryptplug.h
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#ifndef BUG_URL
#define BUG_URL "http:://www.gnupg.org/aegypten/"
#endif

#include "gpgme.h"
#ifndef GPGMEPLUG_PROTOCOL
#define GPGMEPLUG_PROTOCOL GPGME_PROTOCOL_OpenPGP
#endif

// definitions for signing
#ifndef GPGMEPLUG_SIGN_MAKE_MIME_OBJECT
#define GPGMEPLUG_SIGN_INCLUDE_CLEARTEXT true
#define GPGMEPLUG_SIGN_MAKE_MIME_OBJECT  true
#define GPGMEPLUG_SIGN_MAKE_MULTI_MIME   true
#define GPGMEPLUG_SIGN_CTYPE_MAIN        "multipart/signed;protocol=application/pgp-signature;micalg=pgp-sha1"
#define GPGMEPLUG_SIGN_CDISP_MAIN        ""
#define GPGMEPLUG_SIGN_CTENC_MAIN        ""
#define GPGMEPLUG_SIGN_CTYPE_VERSION     ""
#define GPGMEPLUG_SIGN_CDISP_VERSION     ""
#define GPGMEPLUG_SIGN_CTENC_VERSION     ""
#define GPGMEPLUG_SIGN_BTEXT_VERSION     ""
#define GPGMEPLUG_SIGN_CTYPE_CODE        "application/pgp-signature"
#define GPGMEPLUG_SIGN_CDISP_CODE        ""
#define GPGMEPLUG_SIGN_CTENC_CODE        ""
#define GPGMEPLUG_SIGN_FLAT_PREFIX       ""
#define GPGMEPLUG_SIGN_FLAT_SEPARATOR    ""
#define GPGMEPLUG_SIGN_FLAT_POSTFIX      ""
#endif
// definitions for encoding
#ifndef GPGMEPLUG_ENC_MAKE_MIME_OBJECT
#define GPGMEPLUG_ENC_INCLUDE_CLEARTEXT  false
#define GPGMEPLUG_ENC_MAKE_MIME_OBJECT   true
#define GPGMEPLUG_ENC_MAKE_MULTI_MIME    true
#define GPGMEPLUG_ENC_CTYPE_MAIN         "multipart/encrypted; protocol=application/pgp-encrypted"
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
#endif
// Note: The following specification will result in
//       function encryptAndSignMessage() producing
//       _empty_ mails.
//       This must be changed as soon as our plugin
//       is supporting the encryptAndSignMessage() function.
#ifndef GPGMEPLUG_ENCSIGN_MAKE_MIME_OBJECT
#define GPGMEPLUG_ENCSIGN_INCLUDE_CLEARTEXT false
#define GPGMEPLUG_ENCSIGN_MAKE_MIME_OBJECT  false
#define GPGMEPLUG_ENCSIGN_MAKE_MULTI_MIME   false
#define GPGMEPLUG_ENCSIGN_CTYPE_MAIN        ""
#define GPGMEPLUG_ENCSIGN_CDISP_MAIN        ""
#define GPGMEPLUG_ENCSIGN_CTENC_MAIN        ""
#define GPGMEPLUG_ENCSIGN_CTYPE_VERSION     ""
#define GPGMEPLUG_ENCSIGN_CDISP_VERSION     ""
#define GPGMEPLUG_ENCSIGN_CTENC_VERSION     ""
#define GPGMEPLUG_ENCSIGN_BTEXT_VERSION     ""
#define GPGMEPLUG_ENCSIGN_CTYPE_CODE        ""
#define GPGMEPLUG_ENCSIGN_CDISP_CODE        ""
#define GPGMEPLUG_ENCSIGN_CTENC_CODE        ""
#define GPGMEPLUG_ENCSIGN_FLAT_PREFIX       ""
#define GPGMEPLUG_ENCSIGN_FLAT_SEPARATOR    ""
#define GPGMEPLUG_ENCSIGN_FLAT_POSTFIX      ""
#endif

#include "cryptplug.h"


typedef struct {
  const char*             bugURL;
  const char*             signatureKeyCertificate;
  SignatureAlgorithm      signatureAlgorithm;
  SendCertificates        sendCertificates;
  SignEmail               signEmail;
  bool                    saveSentSignatures;
  bool                    warnNoCertificate;
  PinRequests             numPINRequests;
  bool                    checkSignatureCertificatePathToRoot;
  bool                    signatureUseCRLs;
  EncryptionAlgorithm     encryptionAlgorithm;
  EncryptEmail            encryptEmail;
  bool                    saveMessagesEncrypted;
  bool                    checkEncryptionCertificatePathToRoot;
  bool                    encryptionUseCRLs;
  bool                    encryptionCRLExpiryNearWarning;
  int                     encryptionCRLNearExpiryInterval;
  struct DirectoryServer *directoryServers;
  unsigned int            numDirectoryServers;
  CertificateSource       certificateSource;
  CertificateSource       cRLSource;
  bool                    warnSendUnsigned;
  int                     numPINRequestsInterval;
  bool                    signatureCertificateExpiryNearWarning;
  int                     signatureCertificateExpiryNearInterval;
  bool                    cACertificateExpiryNearWarning;
  int                     cACertificateExpiryNearInterval;
  bool                    rootCertificateExpiryNearWarning;
  int                     rootCertificateExpiryNearInterval;
  bool                    warnSendUnencrypted;
  bool                    checkCertificatePath;
  bool                    receiverCertificateExpiryNearWarning;
  int                     receiverCertificateExpiryNearWarningInterval;
  bool                    certificateInChainExpiryNearWarning;
  int                     certificateInChainExpiryNearWarningInterval;
  bool                    receiverEmailAddressNotInCertificateWarning;
} Config;


Config config;

#define NEAR_EXPIRY 14

bool initialize()
{
  config.bugURL                               = malloc( strlen( BUG_URL ) + 1 );
  strcpy( (char* )config.bugURL,                BUG_URL );
  config.signatureKeyCertificate              = malloc( 1 );
  strcpy( (char* )config.signatureKeyCertificate, "" );
  config.signatureAlgorithm                   = SignAlg_SHA1;
  config.sendCertificates                     = SendCert_SendChainWithRoot;
  config.signEmail                            = SignEmail_SignAll;
  config.saveSentSignatures                   = true;
  config.warnNoCertificate                    = true;
  config.numPINRequests                       = PinRequest_Always;
  config.checkSignatureCertificatePathToRoot  = true;
  config.signatureUseCRLs                     = true;
  config.encryptionAlgorithm                  = EncryptAlg_RSA;
  config.encryptEmail                         = EncryptEmail_Ask;
  config.saveMessagesEncrypted                = true;
  config.checkEncryptionCertificatePathToRoot = true;
  config.encryptionUseCRLs                    = true;
  config.encryptionCRLExpiryNearWarning       = true;
  config.encryptionCRLNearExpiryInterval      = NEAR_EXPIRY;
  config.directoryServers                     = NULL;
  config.numDirectoryServers                  = 0;
  config.certificateSource                    = CertSrc_Server;
  config.cRLSource                            = CertSrc_Server;
  config.warnSendUnsigned                             = true;
  config.numPINRequestsInterval                       = NEAR_EXPIRY;
  config.signatureCertificateExpiryNearWarning        = true;
  config.signatureCertificateExpiryNearInterval       = NEAR_EXPIRY;
  config.cACertificateExpiryNearWarning               = true;
  config.cACertificateExpiryNearInterval              = NEAR_EXPIRY;
  config.rootCertificateExpiryNearWarning             = true;
  config.rootCertificateExpiryNearInterval            = NEAR_EXPIRY;
  config.warnSendUnencrypted                          = false;
  config.checkCertificatePath                         = true;
  config.receiverCertificateExpiryNearWarning         = true;
  config.receiverCertificateExpiryNearWarningInterval = NEAR_EXPIRY;
  config.certificateInChainExpiryNearWarning          = true;
  config.certificateInChainExpiryNearWarningInterval  = NEAR_EXPIRY;
  config.receiverEmailAddressNotInCertificateWarning  = true;

  return true;
};


void deinitialize()
{
  unsigned int i;
  for( i = 0; i < config.numDirectoryServers; ++i ) {
    free( (char *)config.directoryServers[i].servername );
    free( (char *)config.directoryServers[i].description );
  }
  free( config.directoryServers );
}


bool hasFeature( Feature flag )
{
  switch ( flag ) {
    case CryptPlugFeat_SignMessages:              return true;
    case CryptPlugFeat_VerifySignatures:          return true;
    case CryptPlugFeat_EncryptMessages:           return true;
    case CryptPlugFeat_DecryptMessages:           return true;
    // undefined or not yet implemented:
    case CryptPlugFeat_undef:                     return false;
    default:                                      return false;
  }
}


const char* bugURL(){ return config.bugURL; }


void unsafeStationery( void** pixmap, const char** menutext, char* accel,
          const char** tooltip, const char** statusbartext ){}

void signedStationery( void** pixmap, const char** menutext, char* accel,
          const char** tooltip, const char** statusbartext ){}

void encryptedStationery( void** pixmap, const char**
          menutext, char* accel,
          const char** tooltip, const char** statusbartext ){}

void signedEncryptedStationery( void** pixmap, const char**
          menutext, char* accel,
          const char** tooltip, const char** statusbartext ){}

const char* signatureConfigurationDialog(){ return 0; }

const char* signatureKeySelectionDialog(){ return 0; }

const char* signatureAlgorithmDialog(){ return 0; }

const char* signatureHandlingDialog(){ return 0; }

void setSignatureKeyCertificate( const char* certificate )
{
  config.signatureKeyCertificate = certificate;
}

const char* signatureKeyCertificate()
{
  return config.signatureKeyCertificate;
}

void setSignatureAlgorithm( SignatureAlgorithm sigAlg )
{
  config.signatureAlgorithm = sigAlg;
}

SignatureAlgorithm signatureAlgorithm()
{
  return config.signatureAlgorithm;
}

void setSendCertificates( SendCertificates sendCert )
{
  config.sendCertificates = sendCert;
}

SendCertificates sendCertificates()
{
  return config.sendCertificates;
}

void setSignEmail( SignEmail signMail )
{
  config.signEmail = signMail;
}

SignEmail signEmail()
{
  return config.signEmail;
}





void setWarnSendUnsigned( bool flag )
{
  config.warnSendUnsigned = flag;
}

bool warnSendUnsigned()
{
  return config.warnSendUnsigned;
}






void setSaveSentSignatures( bool flag )
{
  config.saveSentSignatures = flag;
}

bool saveSentSignatures()
{
  return config.saveSentSignatures;
}

void setWarnNoCertificate( bool flag )
{
  config.warnNoCertificate = flag;
}

bool warnNoCertificate()
{
  return config.warnNoCertificate;
}

void setNumPINRequests( PinRequests reqMode )
{
  config.numPINRequests = reqMode;
}

PinRequests numPINRequests()
{
  return config.numPINRequests;
}





void setNumPINRequestsInterval( int interval )
{
  config.numPINRequestsInterval = interval;
}

int numPINRequestsInterval()
{
  return config.numPINRequestsInterval;
}







void setCheckSignatureCertificatePathToRoot( bool flag )
{
  config.checkSignatureCertificatePathToRoot = flag;
}

bool checkSignatureCertificatePathToRoot()
{
  return config.checkSignatureCertificatePathToRoot;
}

void setSignatureUseCRLs( bool flag )
{
  config.signatureUseCRLs = flag;
}

bool signatureUseCRLs()
{
  return config.signatureUseCRLs;
}






void setSignatureCertificateExpiryNearWarning( bool flag )
{
  config.signatureCertificateExpiryNearWarning = flag;
}

bool signatureCertificateExpiryNearWarning( void )
{
  return config.signatureCertificateExpiryNearWarning;
}

void setSignatureCertificateExpiryNearInterval( int interval )
{
  config.signatureCertificateExpiryNearInterval = interval;
}

int signatureCertificateExpiryNearInterval( void )
{
  return config.signatureCertificateExpiryNearInterval;
}

void setCACertificateExpiryNearWarning( bool flag )
{
  config.cACertificateExpiryNearWarning = flag;
}

bool caCertificateExpiryNearWarning( void )
{
  return config.cACertificateExpiryNearWarning;
}

void setCACertificateExpiryNearInterval( int interval )
{
  config.cACertificateExpiryNearInterval = interval;
}

int caCertificateExpiryNearInterval( void )
{
  return config.cACertificateExpiryNearInterval;
}

void setRootCertificateExpiryNearWarning( bool flag )
{
  config.rootCertificateExpiryNearWarning = flag;
}

bool rootCertificateExpiryNearWarning( void )
{
  return config.rootCertificateExpiryNearWarning;
}

void setRootCertificateExpiryNearInterval( int interval )
{
  config.rootCertificateExpiryNearInterval = interval;
}

int rootCertificateExpiryNearInterval( void )
{
  return config.rootCertificateExpiryNearInterval;
}








const char* encryptionConfigurationDialog(){ return 0; }

const char* encryptionAlgorithmDialog(){ return 0; }

const char* encryptionHandlingDialog(){ return 0; }

const char* encryptionReceiverDialog(){ return 0; }

void setEncryptionAlgorithm( EncryptionAlgorithm cryptAlg )
{
  config.encryptionAlgorithm = cryptAlg;
}

EncryptionAlgorithm encryptionAlgorithm()
{
  return config.encryptionAlgorithm;
}

void setEncryptEmail( EncryptEmail cryptMode )
{
  config.encryptEmail = cryptMode;
}

EncryptEmail encryptEmail()
{
  return config.encryptEmail;
}






void setWarnSendUnencrypted( bool flag )
{
  config.warnSendUnencrypted = flag;
}

bool warnSendUnencrypted()
{
  return config.warnSendUnencrypted;
}









void setSaveMessagesEncrypted( bool flag )
{
  config.saveMessagesEncrypted = flag;
}

bool saveMessagesEncrypted()
{
  return config.saveMessagesEncrypted;
}







void setCheckCertificatePath( bool flag )
{
  config.checkCertificatePath = flag;
}

bool checkCertificatePath()
{
  return config.checkCertificatePath;
}








void setCheckEncryptionCertificatePathToRoot( bool flag )
{
  config.checkEncryptionCertificatePathToRoot = flag;
}

bool checkEncryptionCertificatePathToRoot()
{
  return config.checkEncryptionCertificatePathToRoot;
}







void setReceiverCertificateExpiryNearWarning( bool flag )
{
  config.receiverCertificateExpiryNearWarning = flag;
}

bool receiverCertificateExpiryNearWarning()
{
  return config.receiverCertificateExpiryNearWarning;
}

void setReceiverCertificateExpiryNearWarningInterval( int interval )
{
  config.receiverCertificateExpiryNearWarningInterval = interval;
}

int receiverCertificateExpiryNearWarningInterval()
{
  return config.receiverCertificateExpiryNearWarningInterval;
}

void setCertificateInChainExpiryNearWarning( bool flag )
{
  config.certificateInChainExpiryNearWarning = flag;
}

bool certificateInChainExpiryNearWarning()
{
  return config.certificateInChainExpiryNearWarning;
}

void setCertificateInChainExpiryNearWarningInterval( int interval )
{
  config.certificateInChainExpiryNearWarningInterval = interval;
}

int certificateInChainExpiryNearWarningInterval()
{
  return config.certificateInChainExpiryNearWarningInterval;
}

void setReceiverEmailAddressNotInCertificateWarning( bool flag )
{
  config.receiverEmailAddressNotInCertificateWarning = flag;
}

bool receiverEmailAddressNotInCertificateWarning()
{
  return config.receiverEmailAddressNotInCertificateWarning;
}








void setEncryptionUseCRLs( bool flag )
{
  config.encryptionUseCRLs = flag;
}

bool encryptionUseCRLs()
{
  return config.encryptionUseCRLs;
}

void setEncryptionCRLExpiryNearWarning( bool flag )
{
  config.encryptionCRLExpiryNearWarning = flag;
}

bool encryptionCRLExpiryNearWarning()
{
  return config.encryptionCRLExpiryNearWarning;
}

void setEncryptionCRLNearExpiryInterval( int interval )
{
  config.encryptionCRLNearExpiryInterval = interval;
}

int encryptionCRLNearExpiryInterval()
{
  return config.encryptionCRLNearExpiryInterval;
}


const char* directoryServiceConfigurationDialog(){ return 0; }

void appendDirectoryServer( const char* servername,
                            int         port,
                            const char* description )
{
  struct DirectoryServer *newServers = NULL;
  newServers = realloc( config.directoryServers,
			(1+config.numDirectoryServers) * sizeof *newServers );
  if( newServers ) {
    config.directoryServers = newServers;
    newServers[ config.numDirectoryServers ].servername =
      malloc( 1+strlen( servername ) );
    if( newServers[ config.numDirectoryServers ].servername ) {
      strcpy( (char *)newServers[ config.numDirectoryServers ].servername,
        servername );
      newServers[ config.numDirectoryServers ].description =
        malloc( 1+strlen(  description ) );
      if( newServers[ config.numDirectoryServers ].description ) {
        strcpy( (char *)newServers[ config.numDirectoryServers ].description,
          description );
        newServers[ config.numDirectoryServers ].port = port;
        config.numDirectoryServers += 1;
      }
    }
  }
}

void setDirectoryServers( struct DirectoryServer server[], unsigned int size )
{
  unsigned int i;
  int oldSize = config.numDirectoryServers;
  struct DirectoryServer *newServers = NULL;
  newServers = calloc ( size, sizeof *newServers );
  if( newServers ) {
    for( i=0; i < oldSize; ++i ) {
      free( (char *)config.directoryServers[i].servername );
      free( (char *)config.directoryServers[i].description );
    }
    free( config.directoryServers );
    for( i=0; i < size; ++i ) {
      newServers[ i ].servername = malloc( 1+strlen( server[i].servername ) );
      if( newServers[ i ].servername ) {
        strcpy( (char *)newServers[ i ].servername, server[i].servername );
        newServers[ i ].description = malloc( 1+strlen( server[i].description ) );
        if( newServers[ i ].description ) {
          strcpy( (char *)newServers[ i ].description, server[i].description );
          newServers[ i ].port = server[i].port;
        }
      }
    }
    config.directoryServers = newServers;
    config.numDirectoryServers = size;
  }
}

struct DirectoryServer * directoryServers( int* numServers )
{
  if( numServers )
    *numServers = config.numDirectoryServers;
  return config.directoryServers;
};

void setCertificateSource( CertificateSource source )
{
  config.certificateSource = source;
}

CertificateSource certificateSource()
{
  return config.certificateSource;
}

void setCRLSource( CertificateSource source )
{
  config.cRLSource = source;
}

CertificateSource crlSource()
{
  return config.cRLSource;
}


bool certificateValidity( const char* certificate,
                          int* level ){ return true; }


void storeNewCharPtr( char** dest, const char* src )
{
  int sLen = strlen( src );
  *dest = malloc( sLen + 1 );
  strcpy( *dest, src );
  (*dest)[sLen] = '\0';
}


bool signMessage( const char*  cleartext,
                  const char** ciphertext,
                  const char*  certificate,
                  struct StructuringInfo* structuring )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData data,  sig;
  size_t rSLen = 0;
  char*  rSig  = 0;
  bool   bOk   = false;

  init_StructuringInfo( structuring );

  if( !ciphertext )
    return false;

  err = gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  gpgme_set_armor (ctx, 1);
  gpgme_set_textmode (ctx, 1);

  gpgme_data_new_from_mem (&data, cleartext,
                            1+strlen( cleartext ), 1 );
  gpgme_data_new ( &sig );
  err = gpgme_op_sign (ctx, data, sig, GPGME_SIG_MODE_DETACH );

  if (!err) {
    rSig  = gpgme_data_release_and_get_mem( sig,  &rSLen );
    *ciphertext = malloc( rSLen + 1 );
    if( *ciphertext ) {
      if( rSLen ) {
        bOk = true;
        strncpy((char*)*ciphertext, rSig, rSLen );
      }
      ((char*)(*ciphertext))[rSLen] = '\0';
    }
    free( rSig );
  }
  else {
    gpgme_data_release( sig );
    *ciphertext = 0;
    // hier fehlt eine Fehlerbehandlung, falls das
    // Signieren schiefging
  }
  gpgme_data_release( data );
  gpgme_release (ctx);

  if( bOk && structuring ) {
    structuring->includeCleartext = GPGMEPLUG_SIGN_INCLUDE_CLEARTEXT;
    structuring->makeMimeObject   = GPGMEPLUG_SIGN_MAKE_MIME_OBJECT;
    if( structuring->makeMimeObject ) {
      structuring->makeMultiMime  = GPGMEPLUG_SIGN_MAKE_MULTI_MIME;
      storeNewCharPtr( &structuring->contentTypeMain,
                       GPGMEPLUG_SIGN_CTYPE_MAIN );
      storeNewCharPtr( &structuring->contentDispMain,
                       GPGMEPLUG_SIGN_CDISP_MAIN );
      storeNewCharPtr( &structuring->contentTEncMain,
                       GPGMEPLUG_SIGN_CTENC_MAIN );
      if( structuring->makeMultiMime ) {
        storeNewCharPtr( &structuring->contentTypeVersion,
                         GPGMEPLUG_SIGN_CTYPE_VERSION );
        storeNewCharPtr( &structuring->contentDispVersion,
                         GPGMEPLUG_SIGN_CDISP_VERSION );
        storeNewCharPtr( &structuring->contentTEncVersion,
                         GPGMEPLUG_SIGN_CTENC_VERSION );
        storeNewCharPtr( &structuring->bodyTextVersion,
                         GPGMEPLUG_SIGN_BTEXT_VERSION );
        storeNewCharPtr( &structuring->contentTypeCode,
                         GPGMEPLUG_SIGN_CTYPE_CODE );
        storeNewCharPtr( &structuring->contentDispCode,
                         GPGMEPLUG_SIGN_CDISP_CODE );
        storeNewCharPtr( &structuring->contentTEncCode,
                         GPGMEPLUG_SIGN_CTENC_CODE );
      }
    } else {
      storeNewCharPtr( &structuring->flatTextPrefix,
                       GPGMEPLUG_SIGN_FLAT_PREFIX );
      storeNewCharPtr( &structuring->flatTextSeparator,
                       GPGMEPLUG_SIGN_FLAT_SEPARATOR );
      storeNewCharPtr( &structuring->flatTextPostfix,
                       GPGMEPLUG_SIGN_FLAT_POSTFIX );
    }
  }
  return bOk;
}


static const char*
sig_status_to_string( GpgmeSigStat status )
{
  const char *result;

  switch (status) {
    case GPGME_SIG_STAT_NONE:
      result = "Oops: Signature not verified";
      break;
    case GPGME_SIG_STAT_NOSIG:
      result = "No signature found";
      break;
    case GPGME_SIG_STAT_GOOD:
      result = "Good signature";
      break;
    case GPGME_SIG_STAT_BAD:
      result = "BAD signature";
      break;
    case GPGME_SIG_STAT_NOKEY:
      result = "No public key to verify the signature";
      break;
    case GPGME_SIG_STAT_ERROR:
      result = "Error verifying the signature";
      break;
    case GPGME_SIG_STAT_DIFF:
      result = "Different results for signatures";
      break;
    default:
      result = "Error: Unknown status";
      break;
  }

  return result;
}


bool checkMessageSignature( const char* ciphertext,
                            const char* signaturetext,
                            struct SignatureMetaData* sigmeta )
{
  GpgmeCtx ctx;
  GpgmeSigStat status;
  GpgmeData datapart, sigpart;
  GpgmeError err;
  GpgmeKey key;
  time_t created;
  int sig_idx = 0;
  const char* statusStr;
  const char* fpr;

  gpgme_new( &ctx );
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);
  gpgme_data_new_from_mem( &datapart, ciphertext,
                          1+strlen( ciphertext ), 1 );
  gpgme_data_new_from_mem( &sigpart, signaturetext,
                          1+strlen( signaturetext ), 1 );

  gpgme_op_verify( ctx, sigpart, datapart, &status );
  gpgme_data_release( datapart );
  gpgme_data_release( sigpart );

  /* Provide information in the sigmeta struct */
  /* the status string */
  statusStr = sig_status_to_string( status );
  sigmeta->status = malloc( strlen( statusStr ) + 1 );
  if( sigmeta->status ) {
    strcpy( sigmeta->status, statusStr );
    sigmeta->status[strlen( statusStr )] = '\0';
  } else
    ; // nothing to do, is already 0

  // Extended information for any number of signatures.
  fpr = gpgme_get_sig_status( ctx, sig_idx, &status, &created );
  sigmeta->extended_info = 0;
  while( fpr != NULL ) {
    struct tm* ctime_val;
    const char* sig_status;

    void* realloc_return = realloc( sigmeta->extended_info,
                                    sizeof( struct SignatureMetaDataExtendedInfo ) * ( sig_idx + 1 ) );
    if( realloc_return ) {
      sigmeta->extended_info = realloc_return;
      // the creation time
      sigmeta->extended_info[sig_idx].creation_time = malloc( sizeof( struct tm ) );
      if( sigmeta->extended_info[sig_idx].creation_time ) {
        ctime_val = localtime( &created );
        memcpy( sigmeta->extended_info[sig_idx].creation_time,
                ctime_val, sizeof( struct tm ) );
      }

      err = gpgme_get_sig_key (ctx, sig_idx, &key);
      sig_status = sig_status_to_string( status );
      sigmeta->extended_info[sig_idx].status_text = malloc( strlen( sig_status ) + 1 );
      if( sigmeta->extended_info[sig_idx].status_text ) {
        strcpy( sigmeta->extended_info[sig_idx].status_text,
                sig_status );
        sigmeta->extended_info[sig_idx].status_text[strlen( sig_status )] = '\0';
      }

      sigmeta->extended_info[sig_idx].fingerprint = malloc( strlen( fpr ) + 1 );
      if( sigmeta->extended_info[sig_idx].fingerprint ) {
        strcpy( sigmeta->extended_info[sig_idx].fingerprint, fpr );
        sigmeta->extended_info[sig_idx].fingerprint[strlen( fpr )] = '\0';
      }
    } else
      break; // if allocation fails once, it isn't likely to
              // succeed the next time either

    fpr = gpgme_get_sig_status (ctx, ++sig_idx, &status, &created);
  }
  sigmeta->extended_info_count = sig_idx;
  sigmeta->nota_xml = gpgme_get_notation( ctx );
  sigmeta->status_code = status;

  gpgme_release( ctx );
  return ( status == GPGME_SIG_STAT_GOOD );
}

bool storeCertificatesFromMessage(
        const char* ciphertext ){ return true; }


bool encryptMessage( const char* cleartext,
                     const char** ciphertext,
                     const char* addressee,
                     struct StructuringInfo* structuring )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData gCiphertext, gPlaintext;
  GpgmeRecipients rset;
  size_t rCLen = 0;
  char*  rCiph = 0;
  bool   bOk   = false;

  init_StructuringInfo( structuring );

  gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  gpgme_set_armor (ctx, 1);
  gpgme_set_textmode (ctx, 1);

  gpgme_data_new_from_mem (&gPlaintext, cleartext,
                            1+strlen( cleartext ), 1 );
  err = gpgme_data_new ( &gCiphertext );

  gpgme_recipients_new (&rset);


  if( GPGMEPLUG_PROTOCOL == GPGME_PROTOCOL_CMS )
  {
    gpgme_recipients_add_name_with_validity (rset,
      "/CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=DÃ¼sseldorf,C=DE",
      GPGME_VALIDITY_FULL );
    fputs( "\nGPGSMPLUG encryptMessage() using test key of Aegypten Project\n", stderr );
  }
  else
  {
    gpgme_recipients_add_name (rset, addressee);
    fprintf( stderr, "\nGPGMEPLUG encryptMessage() using addressee %s\n", addressee );
  }


  err = gpgme_op_encrypt (ctx, rset, gPlaintext, gCiphertext );
  if( err )
    fprintf( stderr, "gpgme_op_encrypt() returned this error code:  %i\n\n", err );

  gpgme_recipients_release (rset);
  gpgme_data_release (gPlaintext);

  if( !err ) {
    rCiph = gpgme_data_release_and_get_mem( gCiphertext,  &rCLen );
    *ciphertext = malloc( rCLen + 1 );
    if( *ciphertext ) {
      if( rCLen ) {
        bOk = true;
        strncpy((char*)*ciphertext, rCiph, rCLen );
      }
      ((char*)(*ciphertext))[rCLen] = 0;
    }
    free( rCiph );
  }
  else {
    gpgme_data_release ( gCiphertext );
    *ciphertext = 0;
    // hier fehlt eine Fehlerbehandlung: fuer einen Recipient nur ein
    // untrusted key (oder gar keiner) gefunden wurde, verweigert gpg
    // das signieren.
  }

  gpgme_release (ctx);

  fflush( stderr );

  if( bOk && structuring ) {
    structuring->includeCleartext = GPGMEPLUG_ENC_INCLUDE_CLEARTEXT;
    structuring->makeMimeObject   = GPGMEPLUG_ENC_MAKE_MIME_OBJECT;
    if( structuring->makeMimeObject ) {
      structuring->makeMultiMime  = GPGMEPLUG_ENC_MAKE_MULTI_MIME;
      storeNewCharPtr( &structuring->contentTypeMain,
                       GPGMEPLUG_ENC_CTYPE_MAIN );
      storeNewCharPtr( &structuring->contentDispMain,
                       GPGMEPLUG_ENC_CDISP_MAIN );
      storeNewCharPtr( &structuring->contentTEncMain,
                       GPGMEPLUG_ENC_CTENC_MAIN );
      if( structuring->makeMultiMime ) {
        storeNewCharPtr( &structuring->contentTypeVersion,
                         GPGMEPLUG_ENC_CTYPE_VERSION );
        storeNewCharPtr( &structuring->contentDispVersion,
                         GPGMEPLUG_ENC_CDISP_VERSION );
        storeNewCharPtr( &structuring->contentTEncVersion,
                         GPGMEPLUG_ENC_CTENC_VERSION );
        storeNewCharPtr( &structuring->bodyTextVersion,
                         GPGMEPLUG_ENC_BTEXT_VERSION );
        storeNewCharPtr( &structuring->contentTypeCode,
                         GPGMEPLUG_ENC_CTYPE_CODE );
        storeNewCharPtr( &structuring->contentDispCode,
                         GPGMEPLUG_ENC_CDISP_CODE );
        storeNewCharPtr( &structuring->contentTEncCode,
                         GPGMEPLUG_ENC_CTENC_CODE );
      }
    } else {
      storeNewCharPtr( &structuring->flatTextPrefix,
                       GPGMEPLUG_ENC_FLAT_PREFIX );
      storeNewCharPtr( &structuring->flatTextSeparator,
                       GPGMEPLUG_ENC_FLAT_SEPARATOR );
      storeNewCharPtr( &structuring->flatTextPostfix,
                       GPGMEPLUG_ENC_FLAT_POSTFIX );
    }
  }
  return bOk;
}


bool encryptAndSignMessage( const char* cleartext,
                            const char** ciphertext,
                            const char* certificate,
                            struct StructuringInfo* structuring )
{
  bool bOk;

  init_StructuringInfo( structuring );

  bOk = false;

  // implementation of this function is still missing

  if( bOk && structuring ) {
    structuring->includeCleartext = GPGMEPLUG_ENCSIGN_INCLUDE_CLEARTEXT;
    structuring->makeMimeObject   = GPGMEPLUG_ENCSIGN_MAKE_MIME_OBJECT;
    if( structuring->makeMimeObject ) {
      structuring->makeMultiMime  = GPGMEPLUG_ENCSIGN_MAKE_MULTI_MIME;
      storeNewCharPtr( &structuring->contentTypeMain,
                       GPGMEPLUG_ENCSIGN_CTYPE_MAIN );
      storeNewCharPtr( &structuring->contentDispMain,
                       GPGMEPLUG_ENCSIGN_CDISP_MAIN );
      storeNewCharPtr( &structuring->contentTEncMain,
                       GPGMEPLUG_ENCSIGN_CTENC_MAIN );
      if( structuring->makeMultiMime ) {
        storeNewCharPtr( &structuring->contentTypeVersion,
                         GPGMEPLUG_ENCSIGN_CTYPE_VERSION );
        storeNewCharPtr( &structuring->contentDispVersion,
                         GPGMEPLUG_ENCSIGN_CDISP_VERSION );
        storeNewCharPtr( &structuring->contentTEncVersion,
                         GPGMEPLUG_ENCSIGN_CTENC_VERSION );
        storeNewCharPtr( &structuring->bodyTextVersion,
                         GPGMEPLUG_ENCSIGN_BTEXT_VERSION );
        storeNewCharPtr( &structuring->contentTypeCode,
                         GPGMEPLUG_ENCSIGN_CTYPE_CODE );
        storeNewCharPtr( &structuring->contentDispCode,
                         GPGMEPLUG_ENCSIGN_CDISP_CODE );
        storeNewCharPtr( &structuring->contentTEncCode,
                         GPGMEPLUG_ENCSIGN_CTENC_CODE );
      }
    } else {
      storeNewCharPtr( &structuring->flatTextPrefix,
                       GPGMEPLUG_ENCSIGN_FLAT_PREFIX );
      storeNewCharPtr( &structuring->flatTextSeparator,
                       GPGMEPLUG_ENCSIGN_FLAT_SEPARATOR );
      storeNewCharPtr( &structuring->flatTextPostfix,
                       GPGMEPLUG_ENCSIGN_FLAT_POSTFIX );
    }
  }
  return bOk;
}

bool decryptMessage( const char* ciphertext,
                     const char** cleartext,
                     const char* certificate )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData gCiphertext, gPlaintext;
  size_t rCLen = 0;
  char*  rCiph = 0;
  bool bOk = false;

  if( !ciphertext )
    return false;

  err = gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  gpgme_data_new_from_mem( &gCiphertext, ciphertext,
                           1+strlen( ciphertext ), 1 );
  gpgme_data_new( &gPlaintext );

  gpgme_op_decrypt( ctx, gCiphertext, gPlaintext );
  gpgme_data_release( gCiphertext );

  rCiph = gpgme_data_release_and_get_mem( gPlaintext,  &rCLen );

  *cleartext = malloc( rCLen + 1 );
  if( *cleartext ) {
      if( rCLen ) {
          bOk = true;
          strncpy((char*)*cleartext, rCiph, rCLen );
      }
      ((char*)(*cleartext))[rCLen] = 0;
  }

  free( rCiph );
  gpgme_release( ctx );
  return bOk;
}

bool decryptAndCheckMessage( const char* ciphertext,
          const char** cleartext, const char* certificate,
          struct SignatureMetaData* sigmeta ){ return true; }


const char* requestCertificateDialog(){ return 0; }

bool requestDecentralCertificate( const char* name, const char*
          email, const char* organization, const char* department,
          const char* ca_address ){ return true; }

bool requestCentralCertificateAndPSE( const char* name,
          const char* email, const char* organization, const char* department,
          const char* ca_address ){ return true; }

bool createPSE(){ return true; }

bool registerCertificate( const char* certificate ){ return true; }

bool requestCertificateProlongation( const char* certificate,
                                     const char* ca_address ){ return true; }

const char* certificateChain(){ return 0; }

bool deleteCertificate( const char* certificate ){ return true; }

bool archiveCertificate( const char* certificate ){ return true; }


const char* displayCRL(){ return 0; }

void updateCRL(){}

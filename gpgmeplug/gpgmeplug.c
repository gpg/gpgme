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
#include <ctype.h>

#ifndef BUG_URL
#define BUG_URL "http:://www.gnupg.org/aegypten/"
#endif

#include "gpgme.h"
#ifndef GPGMEPLUG_PROTOCOL
#define GPGMEPLUG_PROTOCOL GPGME_PROTOCOL_OpenPGP
#endif

/* definitions for signing */
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
#define __GPGMEPLUG_SIGNATURE_CODE_IS_BINARY false
#endif
#define __GPGMEPLUG_ERROR_CLEARTEXT_IS_ZERO "Error: Cannot run checkMessageSignature() with cleartext == 0"
/* definitions for encoding */
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
#define __GPGMEPLUG_ENCRYPTED_CODE_IS_BINARY false
#endif
/* Note: The following specification will result in
       function encryptAndSignMessage() producing
       _empty_ mails.
       This must be changed as soon as our plugin
       is supporting the encryptAndSignMessage() function. */
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
  /* our own plugins are supposed to support everything */
  switch ( flag ) {
  case Feature_SignMessages:              return true;
  case Feature_VerifySignatures:          return true;
  case Feature_EncryptMessages:           return true;
  case Feature_DecryptMessages:           return true;
  case Feature_SendCertificates:          return true;
  case Feature_WarnSignCertificateExpiry: return true;
  case Feature_WarnSignEmailNotInCertificate: return true;
  case Feature_PinEntrySettings:          return true;
  case Feature_StoreMessagesWithSigs:     return true;
  case Feature_EncryptionCRLs:            return true;
  case Feature_WarnEncryptCertificateExpiry: return true;
  case Feature_WarnEncryptEmailNotInCertificate: return true;
  case Feature_StoreMessagesEncrypted:    return true;
  case Feature_CheckCertificatePath:      return true;
  case Feature_CertificateDirectoryService: return true;
  case Feature_CRLDirectoryService:       return true;
  /* undefined or not yet implemented: */
  case Feature_undef:                     return false;
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


bool isEmailInCertificate( const char* email, const char* certificate )
{
    /* PENDING(g10) this function should return true if the email
       address passed as the first parameter is contained in the
       certificate passed as the second parameter, and false
       otherwise. This is used to alert the user if his own email
       address is not contained in the certificate he uses for
       signing.
       Note that the parameter email can be anything that is allowed
       in a From: line.
       Another note: OK, OK, we'll handle that in the MUA. You can
       assume that you only get the email address.
    */
  return false; /* dummy*/
}


void setNumPINRequests( PinRequests reqMode )
{
  config.numPINRequests = reqMode;

  /* PENDING(g10) Put this value into gpg and make it ask for the pin
     according to this. Note that there is also
     setNumPINRequestsInterval() which is only used if reqMode ==
     PinRequest_AfterMinutes.
  */
}

PinRequests numPINRequests()
{
  return config.numPINRequests;
}



void setNumPINRequestsInterval( int interval )
{
  config.numPINRequestsInterval = interval;

  /* PENDING(g10) Put this value into gpg and make it ask for the pin
     according to this. Note that this should only be used if
     config.numPINRequests (set with setNumPINRequests()) has the
     value PinRequest_AfterMinutes.
  */
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


int signatureCertificateDaysLeftToExpiry( const char* certificate )
{
  // pending (khz): make this work!
  /*
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeKey rKey;
  time_t daysLeft = 0;

  gpgme_new( &ctx );
  gpgme_set_protocol( ctx, GPGMEPLUG_PROTOCOL );

  err = gpgme_op_keylist_start( ctx, certificate, 0 );
  if ( GPGME_No_Error == err ) {
    err = gpgme_op_keylist_next( ctx, &rKey );
    gpgme_op_keylist_end( ctx );
    if ( GPGME_No_Error == err ) {
      time_t expire_time = gpgme_key_get_ulong_attr(
                             rKey,GPGME_ATTR_EXPIRE, NULL, 0 );
      time_t cur_time = time (NULL);
      daysLeft = expire_time - cur_time;
      // convert seconds into days
      daysLeft /= 43200;
      gpgme_key_release( rKey );
    }
  }
  gpgme_release( ctx );

  return daysLeft;
  */
  return 10;
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

int caCertificateDaysLeftToExpiry( const char* certificate )
{
    /* PENDING(g10)
       Please return the number of days that are left until the
       CA certificate for the certificate specified in the parameter
       certificate expires.
    */
  return 10; /* dummy that triggers a warning in the MUA */
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

int rootCertificateDaysLeftToExpiry( const char* certificate )
{
    /* PENDING(g10)
       Please return the number of days that are left until the
       root certificate for the certificate specified in the parameter
       certificate expires.
    */
  return 10; /* dummy that triggers a warning in the MUA */
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


int receiverCertificateDaysLeftToExpiry( const char* certificate )
{
    /* PENDING(g10)
       Please return the number of days that are left until the
       certificate specified in the parameter certificate expires.
    */
  return 10; /* dummy that triggers a warning in the MUA */
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


int certificateInChainDaysLeftToExpiry( const char* certificate )
{
    /* PENDING(g10)
       Please return the number of days that are left until the
       the first certificate in the chain of the specified certificate
       expires.
    */
  return 10; /* dummy that triggers a warning in the MUA */
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

  /* PENDING(g10) Store this setting in gpgme and use it. If true,
     every certificate used for encryption should be checked against
     applicable CRLs.
  */
}

bool encryptionUseCRLs()
{
  return config.encryptionUseCRLs;
}


int encryptionCRLsDaysLeftToExpiry()
{
    /* PENDING(g10)
       Please return the number of days that are left until the
       CRL used for encryption expires.
    */
  return 10; /* dummy that triggers a warning in the MUA */
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
                  char** ciphertext,
                  const size_t* cipherLen,
                  const char*  certificate,
                  struct StructuringInfo* structuring,
                  int* errId,
                  char** errTxt )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeKey rKey;
  GpgmeData data,  sig;
  char* rSig  = 0;
  bool  bOk   = false;
  int sendCerts = 1;

  init_StructuringInfo( structuring );

  if( !ciphertext )
    return false;

  err = gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  gpgme_set_armor (ctx, __GPGMEPLUG_SIGNATURE_CODE_IS_BINARY ? 0 : 1);
  /*  gpgme_set_textmode (ctx, 1); */

  switch ( config.sendCertificates ) {
    case SendCert_undef:
      break;
    case SendCert_DontSend:
      sendCerts = 0;
      break;
    case SendCert_SendOwn:
      sendCerts = 1;
      break;
    case SendCert_SendChainWithoutRoot:
      sendCerts = -2;
      break;
    case SendCert_SendChainWithRoot:
      sendCerts = -1;
      break;
    default:
      sendCerts = 0;
      break;
  }
  gpgme_set_include_certs (ctx, sendCerts);

  /* select the signer's key if provided */
  if (certificate != 0) {
      err = gpgme_op_keylist_start(ctx, certificate, 0);
      if (err == GPGME_No_Error) {
	  /* we only support one signer for now */
	  err = gpgme_op_keylist_next(ctx, &rKey);
	  if (err == GPGME_No_Error) {
	      /* clear existing signers */
	      gpgme_signers_clear(ctx);
	      /* set the signing key */
	      gpgme_signers_add(ctx, rKey);
	  }
	  gpgme_op_keylist_end(ctx);
      }
  }

  /* PENDING(g10) Implement this

     gpgme_set_signature_algorithm( ctx, config.signatureAlgorithm )
     --> This does not make sense.  The algorithm is a property of
     the certificate used [wk 2002-03-23] */

  gpgme_data_new_from_mem (&data, cleartext,
                            strlen( cleartext ), 1 );
  gpgme_data_new ( &sig );
  err = gpgme_op_sign (ctx, data, sig, GPGME_SIG_MODE_DETACH );

  if ( err == GPGME_No_Error ) {
    if( __GPGMEPLUG_SIGNATURE_CODE_IS_BINARY ) {
      *ciphertext = gpgme_data_release_and_get_mem( sig, (size_t*)cipherLen );
      bOk = true;
    }
    else {
      rSig = gpgme_data_release_and_get_mem( sig, (size_t*)cipherLen );
      *ciphertext = malloc( *cipherLen + 1 );
      if( *ciphertext ) {
        if( *cipherLen ) {
          bOk = true;
          strncpy((char*)*ciphertext, rSig, *cipherLen );
        }
        (*ciphertext)[*cipherLen] = '\0';
      }
      free( rSig );
    }
  }
  else {
    gpgme_data_release( sig );
/*
*ciphertext = malloc( 70 );
strcpy((char*)*ciphertext, "xyz\nsig-dummy\nzyx" );
(*ciphertext)[17] = '\0';
err = 0;
{
*/
    *ciphertext = 0;
    fprintf( stderr, "\n\n    gpgme_op_sign() returned this error code:  %i\n\n", err );
    if( errId )
      *errId = err;
    if( errTxt ) {
      const char* _errTxt = gpgme_strerror( err );
      *errTxt = malloc( strlen( _errTxt ) + 1 );
      if( *errTxt )
        strcpy(*errTxt, _errTxt );
    }
/*
}
*/
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


bool checkMessageSignature( char** cleartext,
                            const char* signaturetext,
                            bool signatureIsBinary,
                            int signatureLen,
                            struct SignatureMetaData* sigmeta )
{
  GpgmeCtx ctx;
  GpgmeSigStat status;
  GpgmeData datapart, sigpart;
  char* rClear = 0;
  size_t clearLen;
  GpgmeError err;
  GpgmeKey key;
  time_t created;
  int sig_idx = 0;
  const char* statusStr;
  const char* fpr;
  bool isOpaqueSigned;

  if( !cleartext ) {
    if( sigmeta )
      storeNewCharPtr( &sigmeta->status,
                        __GPGMEPLUG_ERROR_CLEARTEXT_IS_ZERO );

    return false;
  }

  isOpaqueSigned = !*cleartext;

  gpgme_new( &ctx );
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);
  gpgme_set_armor (ctx,    signatureIsBinary ? 0 : 1);
  /*  gpgme_set_textmode (ctx, signatureIsBinary ? 0 : 1); */

  if( isOpaqueSigned )
    gpgme_data_new( &datapart );
  else
    gpgme_data_new_from_mem( &datapart, *cleartext,
                             strlen( *cleartext ), 1 );

  gpgme_data_new_from_mem( &sigpart,
                           signaturetext,
                           signatureIsBinary
                           ? signatureLen
                           : strlen( signaturetext ),
                           1 );

  gpgme_op_verify( ctx, sigpart, datapart, &status );

  if( isOpaqueSigned ) {
    rClear = gpgme_data_release_and_get_mem( datapart, &clearLen );
    *cleartext = malloc( clearLen + 1 );
    if( *cleartext ) {
      if( clearLen )
        strncpy(*cleartext, rClear, clearLen );
      (*cleartext)[clearLen] = '\0';
    }
    free( rClear );
  }
  else
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
    ; /* nothing to do, is already 0 */

  /* Extended information for any number of signatures. */
  fpr = gpgme_get_sig_status( ctx, sig_idx, &status, &created );
  sigmeta->extended_info = 0;
  while( fpr != NULL ) {
    struct tm* ctime_val;
    const char* sig_status;

    void* realloc_return = realloc( sigmeta->extended_info,
                                    sizeof( struct SignatureMetaDataExtendedInfo ) * ( sig_idx + 1 ) );
    if( realloc_return ) {
      sigmeta->extended_info = realloc_return;

      /* clear the data area */
      memset( &sigmeta->extended_info[sig_idx], 0, sizeof (struct SignatureMetaDataExtendedInfo) );

      /* the creation time */
      sigmeta->extended_info[sig_idx].creation_time = malloc( sizeof( struct tm ) );
      if( sigmeta->extended_info[sig_idx].creation_time ) {
        ctime_val = localtime( &created );
        memcpy( sigmeta->extended_info[sig_idx].creation_time,
                ctime_val, sizeof( struct tm ) );
      }

      sigmeta->extended_info[sig_idx].validity = GPGME_VALIDITY_UNKNOWN;

      err = gpgme_get_sig_key (ctx, sig_idx, &key);

      if ( err == GPGME_No_Error) {
        const char* attr_string;
        unsigned long attr_ulong;

        /* extract key identidy */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_KEYID, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].keyid, attr_string );

        /* extract finger print */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_FPR, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].fingerprint,
                            attr_string );

        /* algorithms useable with this key */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_ALGO, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].algo,
                            attr_string );
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_ALGO, 0, 0);
        sigmeta->extended_info[sig_idx].algo_num = attr_ulong;

        /* extract key validity */
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_VALIDITY, 0, 0);
        sigmeta->extended_info[sig_idx].validity = attr_ulong;

        /* extract user id, according to the documentation it's representable
        * as a number, but it seems that it also has a string representation
        */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_USERID, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].userid,
                            attr_string );
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_USERID, 0, 0);
        sigmeta->extended_info[sig_idx].userid_num = attr_ulong;

        /* extract the length */
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_LEN, 0, 0);
        sigmeta->extended_info[sig_idx].keylen = attr_ulong;

        /* extract the creation time of the key */
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_CREATED, 0, 0);
        sigmeta->extended_info[sig_idx].key_created = attr_ulong;

        /* extract the expiration time of the key */
        attr_ulong = gpgme_key_get_ulong_attr(key, GPGME_ATTR_EXPIRE, 0, 0);
        sigmeta->extended_info[sig_idx].key_expires = attr_ulong;

        /* extract user name */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_NAME, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].name,
                            attr_string );

        /* extract email */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_EMAIL, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].email,
                            attr_string );

        /* extract the comment */
        attr_string = gpgme_key_get_string_attr(key, GPGME_ATTR_COMMENT, 0, 0);
        if (attr_string != 0)
            storeNewCharPtr( &sigmeta->extended_info[sig_idx].comment,
                            attr_string );
      }
      else
        storeNewCharPtr( &sigmeta->extended_info[sig_idx].fingerprint, fpr );

      sig_status = sig_status_to_string( status );
      storeNewCharPtr( &sigmeta->extended_info[sig_idx].status_text,
                       sig_status );

    } else
      break; /* if allocation fails once, it isn't likely to
                succeed the next time either */

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


/* returns address if address doesn't contain a <xxx> part
 * else it returns a new string xxx and frees address
 */
static char* parseAddress( char* address )
{
  char* result = address;
  char* i;
  char* j;
  if( !result ) return result;
  i = index( address, '<' );
  if( i ) {
    j = index( i+1, '>' );
    if( j == NULL ) j = address+strlen(address);
    result = malloc( j-i );
    strncpy( result, i+1, j-i-1 );
    result[j-i-1] = '\0';
    free( address );
  } else {
    i = address;
    j = i+strlen(address);
  }
  {
    /* remove surrounding whitespace */
    char* k = result+(j-i-1);
    char* l = result;
    while( isspace( *l ) ) ++l;
    while( isspace( *k ) ) --k;
    if( l != result || k != result+(j-i-1) ) {
      char* result2 = malloc( k-l+2 );
      strncpy( result2, l, k-l+1 );
      result2[k-l+1] = '\0';
      free(result);
      result = result2;
    }
  }
  return result;
}

static char* nextAddress( const char** address )
{
  const char *start = *address;
  char* result = NULL;
  int quote = 0;
  int comment = 0;
  int found = 0;
  if( *address == NULL ) return NULL;
  while( **address ) {

    switch( **address ) {
    case '\\': /* escaped character */
      ++(*address);
      break;
    case '"':
      if( comment == 0 ) {
        if( quote > 0 ) --quote;
        else ++quote;
      }
      break;
    case '(': /* comment start */
      if( quote == 0 ) ++comment;
      break;
    case ')': /* comment end */
      if( quote == 0 ) --comment;
      break;
    case '\0':
    case '\1': /* delimiter */
      if( quote == 0 && comment == 0 ) {
        found = 1;
      }
      break;
    }
    ++(*address);
    if( found ) break;
  }
  if( found || **address == 0 ) {
    size_t len;
    len = *address - start;
    if( len > 0 ) {
      if( **address != 0 ) --len;
      result = malloc( len*sizeof(char)+1 );
      strncpy( result, start, len );
      result[len] = '\0';
    }
  }
  return parseAddress(result);
}

/*
  Find all certificate for a given addressee and return them in a
  '\1' separated list.
  NOTE: The certificate parameter must point to an allready allocated
  block of memory which is large enough to hold the complete list.
*/
bool findCertificates( const char* addressee, char** certificates )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeKey rKey;
  const char *s;
  const char *s2;
  int nFound = 0;

  strcpy( *certificates, "" );

  gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  err = gpgme_op_keylist_start(ctx, addressee, 0);
  while( GPGME_No_Error == err ) {
    err = gpgme_op_keylist_next(ctx, &rKey);
    if( GPGME_No_Error == err ) {
      s = gpgme_key_get_string_attr (rKey, GPGME_ATTR_USERID, NULL, 0);
      if( s ) {
        s2 = gpgme_key_get_string_attr (rKey, GPGME_ATTR_FPR, NULL, 0);
        if( s2 ) {
          if( nFound )
            strcat(*certificates,"\1" );
          strcat( *certificates, s );
          strcat( *certificates, "    (" );
          strcat( *certificates, s2 );
          strcat( *certificates, ")" );
          ++nFound;
        }
      }
    }
  }
  gpgme_op_keylist_end( ctx );
  gpgme_release (ctx);

  return ( 0 < nFound );
}

bool encryptMessage( const char*  cleartext,
                     const char** ciphertext,
                     const size_t* cipherLen,
                     const char*  certificate,
                     struct StructuringInfo* structuring,
                     int* errId,
                     char** errTxt )
{
  GpgmeCtx ctx;
  GpgmeError err;
  GpgmeData gCiphertext, gPlaintext;
  GpgmeRecipients rset;
  char*  rCiph = 0;
  bool   bOk   = false;

  init_StructuringInfo( structuring );

  gpgme_new (&ctx);
  gpgme_set_protocol (ctx, GPGMEPLUG_PROTOCOL);

  gpgme_set_armor (ctx, __GPGMEPLUG_ENCRYPTED_CODE_IS_BINARY ? 0 : 1);
  /*  gpgme_set_textmode (ctx, 1); */

  gpgme_data_new_from_mem (&gPlaintext, cleartext,
                            1+strlen( cleartext ), 1 );
  err = gpgme_data_new ( &gCiphertext );

  gpgme_recipients_new (&rset);

  /*
  if( GPGMEPLUG_PROTOCOL == GPGME_PROTOCOL_CMS )
  {
    gpgme_recipients_add_name (rset,
      "/CN=test cert 1,OU=Aegypten Project,O=g10 Code GmbH,L=DÃ¼sseldorf,C=DE" );

    fputs( "\nGPGSMPLUG encryptMessage() using test key of Aegypten Project\n", stderr );
  }
  else
  */
  {
    const char* p = certificate;
    char* tok;
    while( (tok = nextAddress( &p ) ) != 0 ) {
      gpgme_recipients_add_name (rset, tok );
      fprintf( stderr, "\nGPGMEPLUG encryptMessage() using addressee %s\n", tok );
      free(tok);
    }
  }

  /* PENDING(g10) Implement this
     Possible values: RSA = 1, SHA1 = 2, TripleDES = 3
     gpgme_set_encryption_algorithm( ctx, config.encryptionAlgorithm );

     -> Your are mixing public key and symmetric algorithms.  The
     latter may be configured but the sphix specifications do opnly
     allow 3-DES so this is not nothing we need to do.  The proper way
     to select the symmetric algorithm is anyway by looking at the
     capabilities of the certificate because this is the only way to
     know what the recipient can accept. [wk 2002-03-23]

     PENDING(g10) Implement this
     gpgme_set_encryption_check_certificate_path(
     config.checkCertificatePath )

     PENDING(g10) Implement this
     gpgme_set_encryption_check_certificate_path_to_root(
     config.checkEncryptionCertificatePathToRoot )

     -> Not checking a certificate up to the ROOT CA is dangerous and
     stupid. There is no need for those options.  [wk 2002-03-23] */



  err = gpgme_op_encrypt (ctx, rset, gPlaintext, gCiphertext );
  if( err ) {
    fprintf( stderr, "\ngpgme_op_encrypt() returned this error code:  %i\n\n", err );
    if( errId )
      *errId = err;
    if( errTxt ) {
      const char* _errTxt = gpgme_strerror( err );
      *errTxt = malloc( strlen( _errTxt ) + 1 );
      if( *errTxt )
        strcpy(*errTxt, _errTxt );
    }
  }

  gpgme_recipients_release (rset);
  gpgme_data_release (gPlaintext);

  if( err == GPGME_No_Error ) {
    if( __GPGMEPLUG_ENCRYPTED_CODE_IS_BINARY ) {
      *ciphertext = gpgme_data_release_and_get_mem( gCiphertext, (size_t*)cipherLen );
      bOk = true;
    }
    else {
      rCiph = gpgme_data_release_and_get_mem( gCiphertext, (size_t*)cipherLen );
      *ciphertext = malloc( *cipherLen + 1 );
      if( *ciphertext ) {
        if( *cipherLen ) {
          bOk = true;
          strncpy((char*)*ciphertext, rCiph, *cipherLen );
        }
        ((char*)(*ciphertext))[*cipherLen] = 0;
      }
      free( rCiph );
    }
  }
  else {
    gpgme_data_release ( gCiphertext );
    *ciphertext = 0;
    /* error handling is missing: if only one untrusted key was found
      (or none at all), gpg won't sign the message.  (hier fehlt eine
      Fehlerbehandlung: fuer einen Recipient nur ein untrusted key
      (oder gar keiner) gefunden wurde, verweigert gpg das signieren.)
    */
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

  /* implementation of this function is still missing */

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
                     bool        cipherIsBinary,
                     int         cipherLen,
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
  
  gpgme_set_armor (ctx, cipherIsBinary ? 0 : 1);
  /*  gpgme_set_textmode (ctx, cipherIsBinary ? 0 : 1); */

  /*
  gpgme_data_new_from_mem( &gCiphertext, ciphertext,
                           1+strlen( ciphertext ), 1 ); */
  gpgme_data_new_from_mem( &gCiphertext,
                           ciphertext,
                           cipherIsBinary
                           ? cipherLen
                           : strlen( ciphertext ),
                           1 );

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

bool requestDecentralCertificate( const char* certparms, 
                                  char** generatedKey, int* length )
{
    GpgmeError err;
    GpgmeCtx ctx;
    GpgmeData pub;
    int len;

    err = gpgme_data_new (&pub);
    fprintf( stderr,  "1: gpgme returned %d\n", err );
    if( err != GPGME_No_Error )
        return false;

    err = gpgme_new (&ctx);
    fprintf( stderr,  "2: gpgme returned %d\n", err );
    if( err != GPGME_No_Error ) {
        gpgme_data_release( pub );
        return false;
    }

    gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);
    /* Don't ASCII-armor, the MUA will use base64 encoding */
    /*    gpgme_set_armor (ctx, 1); */
    err = gpgme_op_genkey (ctx, certparms, pub, NULL );
    fprintf( stderr,  "3: gpgme returned %d\n", err );
    if( err != GPGME_No_Error ) {
        gpgme_data_release( pub );
        gpgme_release( ctx );
        return false;
    }

    gpgme_release (ctx);
    *generatedKey = gpgme_data_release_and_get_mem (pub, &len);
    *length = len;

    /* The buffer generatedKey contains the LEN bytes you want */
    // Caller is responsible for freeing
    return true;
}

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

/*
 * Copyright (C) 2002 g10 Code GmbH
 * 
 *     This program is free software; you can redistribute it
 *     and/or modify it under the terms of the GNU General Public
 *     License as published by the Free Software Foundation; either
 *     version 2 of the License, or (at your option) any later
 *     version.
 * 
 *     This program is distributed in the hope that it will be
 *     useful, but WITHOUT ANY WARRANTY; without even the implied
 *     warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *     PURPOSE.  See the GNU General Public License for more
 *     details.
 * 
 *     You should have received a copy of the GNU General Public
 *     License along with this program; if not, write to the Free
 *     Software Foundation, Inc., 59 Temple Place - Suite 330,
 *     Boston, MA  02111, USA.
 */

/* Max number of parts in a DN */
#define MAX_GPGME_IDX 20

/* some macros to replace ctype ones and avoid locale problems */
#define spacep(p)   (*(p) == ' ' || *(p) == '\t')
#define digitp(p)   (*(p) >= '0' && *(p) <= '9')
#define hexdigitp(a) (digitp (a)                     \
                      || (*(a) >= 'A' && *(a) <= 'F')  \
                      || (*(a) >= 'a' && *(a) <= 'f'))
/* the atoi macros assume that the buffer has only valid digits */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))
#define xtoi_1(p)   (*(p) <= '9'? (*(p)- '0'): \
                     *(p) <= 'F'? (*(p)-'A'+10):(*(p)-'a'+10))
#define xtoi_2(p)   ((xtoi_1(p) * 16) + xtoi_1((p)+1))

#define safe_malloc( x ) malloc( x )
#define xstrdup( x ) (x)?strdup(x):0

static void safe_free( void** x ) 
{
  free( *x );
  *x = 0;
}
/*#define safe_free( x ) free( x )*/

/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
static const unsigned char *
parse_dn_part (struct DnPair *array, const unsigned char *string)
{
  const unsigned char *s, *s1;
  size_t n;
  unsigned char *p;

  /* parse attributeType */
  for (s = string+1; *s && *s != '='; s++)
    ;
  if (!*s)
    return NULL; /* error */
  n = s - string;
  if (!n)
    return NULL; /* empty key */
  array->key = p = safe_malloc (n+1);
  memcpy (p, string, n); /* fixme: trim trailing spaces */
  p[n] = 0;
  string = s + 1;

  if (*string == '#')
    { /* hexstring */
      string++;
      for (s=string; hexdigitp (s); s++)
        s++;
      n = s - string;
      if (!n || (n & 1))
        return NULL; /* empty or odd number of digits */
      n /= 2;
      array->value = p = safe_malloc (n+1);
      for (s1=string; n; s1 += 2, n--)
        *p++ = xtoi_2 (s1);
      *p = 0;
   }
  else
    { /* regular v3 quoted string */
      for (n=0, s=string; *s; s++)
        {
          if (*s == '\\')
            { /* pair */
              s++;
              if (*s == ',' || *s == '=' || *s == '+'
                  || *s == '<' || *s == '>' || *s == '#' || *s == ';' 
                  || *s == '\\' || *s == '\"' || *s == ' ')
                n++;
              else if (hexdigitp (s) && hexdigitp (s+1))
                {
                  s++;
                  n++;
                }
              else
                return NULL; /* invalid escape sequence */
            }
          else if (*s == '\"')
            return NULL; /* invalid encoding */
          else if (*s == ',' || *s == '=' || *s == '+'
                   || *s == '<' || *s == '>' || *s == '#' || *s == ';' )
            break; 
          else
            n++;
        }

      array->value = p = safe_malloc (n+1);
      for (s=string; n; s++, n--)
        {
          if (*s == '\\')
            { 
              s++;
              if (hexdigitp (s))
                {
                  *p++ = xtoi_2 (s);
                  s++;
                }
              else
                *p++ = *s;
            }
          else
            *p++ = *s;
        }
      *p = 0;
    }
  return s;
}


/* Parse a DN and return an array-ized one.  This is not a validating
   parser and it does not support any old-stylish syntax; gpgme is
   expected to return only rfc2253 compatible strings. */
static struct DnPair *
parse_dn (const unsigned char *string)
{
  struct DnPair *array;
  size_t arrayidx, arraysize;
  int i;

  arraysize = 7; /* C,ST,L,O,OU,CN,email */
  array = safe_malloc ((arraysize+1) * sizeof *array);
  arrayidx = 0;
  while (*string)
    {
      while (*string == ' ')
        string++;
      if (!*string)
        break; /* ready */
      if (arrayidx >= arraysize)
        { /* mutt lacks a real safe_realoc - so we need to copy */
          struct DnPair *a2;

          arraysize += 5;
          a2 = safe_malloc ((arraysize+1) * sizeof *array);
          for (i=0; i < arrayidx; i++)
            {
              a2[i].key = array[i].key;
              a2[i].value = array[i].value;
            }
          safe_free ((void **)&array);
          array = a2;
        }
      array[arrayidx].key = NULL;
      array[arrayidx].value = NULL;
      string = parse_dn_part (array+arrayidx, string);
      arrayidx++;
      if (!string)
        goto failure;
      while (*string == ' ')
        string++;
      if (*string && *string != ',' && *string != ';' && *string != '+')
        goto failure; /* invalid delimiter */
      if (*string)
        string++;
    }
  array[arrayidx].key = NULL;
  array[arrayidx].value = NULL;
  return array;

 failure:
  for (i=0; i < arrayidx; i++)
    {
      safe_free ((void**)&array[i].key);
      safe_free ((void**)&array[i].value);
    }
  safe_free ((void**)&array);
  return NULL;
}

static int add_dn_part( char* result, struct DnPair* dn, const char* part )
{
  int any = 0;

  for(; dn->key; ++dn ) {
    if( !strcmp( dn->key, part ) ) {
      if( any ) strcat( result, "+" );
      strcat( result, dn->value );
      any = 1;
    }
  }
  return any;
}

static char* reorder_dn( struct DnPair *dn )
{
  const char* stdpart[] = {
    "CN", "OU", "O", "STREET", "L", "ST", "C", NULL 
  };
  int any=0, any2=0, len=0, i;
  char* result;
  for( i = 0; dn[i].key; ++i ) {
    len += strlen( dn[i].key );
    len += strlen( dn[i].value );
    len += 4; /* ',' and '=', and possibly "(" and ")" */
  }
  result = (char*)safe_malloc( (len+1)*sizeof(char) );
  *result = 0;

  /* add standard parts */
  for( i = 0; stdpart[i]; ++i ) {
    if( any ) {
      strcat( result, "," );
    }
    any = add_dn_part( result, dn, stdpart[i] );
  }

  /* add remaining parts in no particular order */
  for(; dn->key; ++dn ) {
    for( i = 0; stdpart[i]; ++i ) {
      if( !strcmp( dn->key, stdpart[i] ) ) {
	break;
      }
    }
    if( !stdpart[i] ) {
      if( any ) strcat( result, "," );
      if( !any2 ) strcat( result, "(");
      any = add_dn_part( result, dn, dn->key );
      any2 = 1;
    }
  }
  if( any2 ) strcat( result, ")");
  return result;
}

struct CertIterator {
  GpgmeCtx ctx;  
  struct CertificateInfo info;
};

struct CertIterator* startListCertificates( const char* pattern )
{
    GpgmeError err;
    struct CertIterator* it;
    /*fprintf( stderr,  "startListCertificates()" );*/

    it = (struct CertIterator*)safe_malloc( sizeof( struct CertIterator ) );

    err = gpgme_new (&(it->ctx));
    /*fprintf( stderr,  "2: gpgme returned %d\n", err );*/
    if( err != GPGME_No_Error ) {
      free( it );
      return NULL;
    }

    gpgme_set_protocol (it->ctx, GPGME_PROTOCOL_CMS);
    err =  gpgme_op_keylist_start ( it->ctx, pattern, 0);
    if( err != GPGME_No_Error ) {
      endListCertificates( it );
      return NULL;
    }
    memset( &(it->info), 0, sizeof( struct CertificateInfo ) );
    return it;
}

static void freeStringArray( char** c )
{
    char** _c = c;
    while( c && *c ) {
      /*fprintf( stderr, "freeing \"%s\"\n", *c );*/
      safe_free( (void**)&(*c) );
      ++c;
    }
    safe_free( (void**)&_c );
}

static void freeInfo( struct CertificateInfo* info )
{
  struct DnPair* a = info->dnarray;
  assert( info );
  if( info->userid ) freeStringArray( info->userid );
  if( info->serial ) safe_free( (void**)&(info->serial) );
  if( info->fingerprint ) safe_free( (void**)&(info->fingerprint) );
  if( info->issuer ) safe_free( (void**)&(info->issuer) );
  if( info->chainid ) safe_free( (void**)&(info->chainid) );
  if( info->caps ) safe_free( (void**)&(info->caps) );
  while( a && a->key && a->value ) {
    safe_free ((void**)&(a->key));
    safe_free ((void**)&(a->value));
    ++a;
  }
  if( info->dnarray ) safe_free ((void**)&(info->dnarray));
  memset( info, 0, sizeof( *info ) );
}

static char* make_fingerprint( const char* fpr )
{
  int len = strlen(fpr);
  int i = 0;
  char* result = safe_malloc( (len + len/2 + 1)*sizeof(char) );
  if( !result ) return NULL;
  for(; *fpr; ++fpr, ++i ) {
    if( i%3 == 2) {
      result[i] = ':'; ++i;
    }
    result[i] = *fpr;
  }
  result[i] = 0;
  return result;
}

struct CertificateInfo* nextCertificate( struct CertIterator* it )
{
  GpgmeError err;
  GpgmeKey   key;
  assert( it );
  err = gpgme_op_keylist_next ( it->ctx, &key);
  if( err != GPGME_EOF ) {   
    int idx;
    const char* s;
    unsigned long u;
    char* names[MAX_GPGME_IDX+1];
    memset( names, 0, sizeof( names ) );
    freeInfo( &(it->info) );

    for( idx = 0; (s = gpgme_key_get_string_attr (key, GPGME_ATTR_USERID, 0, idx)) && idx < MAX_GPGME_IDX; 
	 ++idx ) {
      names[idx] = xstrdup( s );
    }
    
    it->info.userid = safe_malloc( sizeof( char* ) * (idx+1) );
    memset( it->info.userid, 0, sizeof( char* ) * (idx+1) );
    it->info.dnarray = 0;
    for( idx = 0; names[idx] != 0; ++idx ) {
      struct DnPair* a = parse_dn( names[idx] ); 
      if( idx == 0 ) {
	it->info.userid[idx] = reorder_dn( a );
	safe_free( &(names[idx]) );
      } else {
	it->info.userid[idx] = names[idx];
	it->info.dnarray = a;
      }
    }
    it->info.userid[idx] = 0;

    s = gpgme_key_get_string_attr (key, GPGME_ATTR_SERIAL, 0, 0); 
    it->info.serial = xstrdup(s);

    s = gpgme_key_get_string_attr (key, GPGME_ATTR_FPR, 0, 0); 
    it->info.fingerprint = make_fingerprint( s );

    s = gpgme_key_get_string_attr (key, GPGME_ATTR_ISSUER, 0, 0); 
    it->info.issuer = xstrdup(s);

    s = gpgme_key_get_string_attr (key, GPGME_ATTR_CHAINID, 0, 0); 
    it->info.chainid = xstrdup(s);

    s = gpgme_key_get_string_attr (key, GPGME_ATTR_KEY_CAPS, 0, 0); 
    it->info.caps = xstrdup(s);

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_CREATED, 0, 0); 
    it->info.created = u;

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_EXPIRE, 0, 0); 
    it->info.expire = u;

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_IS_SECRET, 0, 0); 
    it->info.secret = u;

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_UID_INVALID, 0, 0); 
    it->info.invalid = u;

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_KEY_EXPIRED, 0, 0); 
    it->info.expired = u;

    u = gpgme_key_get_ulong_attr (key, GPGME_ATTR_KEY_DISABLED, 0, 0); 
    it->info.disabled = u;

    gpgme_key_release (key);
    return &(it->info);
  } else return NULL;
}

void endListCertificates( struct CertIterator* it )
{
  /*fprintf( stderr,  "endListCertificates()\n" );*/
  assert(it);
  freeInfo( &(it->info) );
  gpgme_op_keylist_end(it->ctx);
  gpgme_release (it->ctx);
  free( it );
}

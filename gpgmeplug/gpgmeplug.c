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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <gpgme.h>

#include "cryptplug.h"


typedef struct {
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
  config.signatureKeyCertificate              = "";
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
      malloc( strlen( servername ) );
    if( newServers[ config.numDirectoryServers ].servername ) {
      strcpy( (char *)newServers[ config.numDirectoryServers ].servername,
        servername );
      newServers[ config.numDirectoryServers ].description =
        malloc( strlen(  description ) );
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
      newServers[ i ].servername = malloc( strlen( server[i].servername ) );
      if( newServers[ i ].servername ) {
        strcpy( (char *)newServers[ i ].servername, server[i].servername );
        newServers[ i ].description = malloc( strlen( server[i].description ) );
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


bool signMessage( const char*  cleartext,
                  const char** ciphertext,
                  const char*  certificate )
{
  GpgmeCtx ctx;
  GpgmeData data, sig;

  char buf[1024];
  size_t nread;

  
  gpgme_new (&ctx);
  gpgme_set_armor (ctx, 1);
  gpgme_set_textmode (ctx, 1);

  gpgme_data_new_from_mem (&data, cleartext,
                            strlen( cleartext ), 1 );
  gpgme_data_new ( &sig );
  gpgme_op_sign (ctx, data, sig, GPGME_SIG_MODE_DETACH );

  fputs ( "Content-Type: multipart/signed;\r\n"
          "              protocol=\"application/pgp-signature\";\r\n"
          "              boundary=\"42=.42=.42=.42\"\r\n"
          "\r\n--42=.42=.42=.42\r\n",
          stdout );

  gpgme_data_rewind (data);
  while ( !gpgme_data_read (data, buf, sizeof buf, &nread ) ) {
        fwrite (buf, nread, 1, stdout );
  }
  fputs ( "\r\n--42=.42=.42=.42\r\n"
          "Content-Type: application/pgp-signature\r\n\r\n", stdout);

  gpgme_data_rewind (sig);
  while ( !gpgme_data_read (sig, buf, sizeof buf, &nread ) ) {
        fwrite (buf, nread, 1, stdout );
  }
  fputs ( "\r\n--42=.42=.42=.42--\r\n", stdout );

  gpgme_release (ctx);
  gpgme_data_release(data);
  gpgme_data_release(sig);

  return true;
}

bool checkMessageSignature( const char* ciphertext, const char**
        cleartext, struct SignatureMetaData* sigmeta ){ return true; }

bool storeCertificatesFromMessage(
        const char* ciphertext ){ return true; }


bool encryptMessage( const char* cleartext,
                     const char** ciphertext ){ return true; }

bool encryptAndSignMessage( const char* cleartext,
          const char** ciphertext, const char* certificate,
          struct SignatureMetaData* sigmeta ){ return true; }

bool decryptMessage( const char* ciphertext, const
          char** cleartext, const char* certificate ){ return true; }

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

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

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <gpgme.h>
#include <util.h>

#include "cryptplug.h"


typedef struct {
  const char*             signatureKeyCertificate;
  SignatureAlgorithm      signatureAlgorithm;
  SendCertificates        sendCertificates;
  SignEmail               signEmail;
  bool                    saveSentSignatures;
  bool                    certificateExpiryNearWarning;
  bool                    warnNoCertificate;
  PinRequests             numPINRequests;
  bool                    checkSignatureCertificatePathToRoot;
  bool                    signatureUseCRLs;
  bool                    signatureCRLExpiryNearWarning;
  int                     signatureCRLNearExpiryInterval;
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
} Config;


Config config;


#define NEAR_EXPIRY 21

bool initialize()
{
  config.signatureKeyCertificate              = "";
  config.signatureAlgorithm                   = SignAlg_SHA1;
  config.sendCertificates                     = SendCert_SendChainWithRoot;
  config.signEmail                            = SignEmail_SignAll;
  config.saveSentSignatures                   = true;
  config.certificateExpiryNearWarning         = true;
  config.warnNoCertificate                    = true;
  config.numPINRequests                       = PinRequest_Always;
  config.checkSignatureCertificatePathToRoot  = true;
  config.signatureUseCRLs                     = true;
  config.signatureCRLExpiryNearWarning        = true;
  config.signatureCRLNearExpiryInterval       = NEAR_EXPIRY;
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
  return true;
};


void deinitialize()
{
  _gpgme_free( config.directoryServers );
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

void setSaveSentSignatures( bool flag )
{
  config.saveSentSignatures = flag;
}

bool saveSentSignatures()
{
  return config.saveSentSignatures;
}

void setCertificateExpiryNearWarning( bool flag )
{
  config.certificateExpiryNearWarning = flag;
}

bool certificateExpiryNearWarning()
{
  return config.certificateExpiryNearWarning;
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

void setSignatureCRLExpiryNearWarning( bool flag )
{
  config.signatureCRLExpiryNearWarning = flag;
}

bool signatureCRLExpiryNearWarning()
{
  return config.signatureCRLExpiryNearWarning;
}

void setSignatureCRLNearExpiryInterval( int interval )
{
  config.signatureCRLNearExpiryInterval = interval;
}

int signatureCRLNearExpiryInterval()
{
  return config.signatureCRLNearExpiryInterval;
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

void setSaveMessagesEncrypted( bool flag )
{
  config.saveMessagesEncrypted = flag;
}

bool saveMessagesEncrypted()
{
  return config.saveMessagesEncrypted;
}

void setCheckEncryptionCertificatePathToRoot( bool flag )
{
  config.checkEncryptionCertificatePathToRoot = flag;
}

bool checkEncryptionCertificatePathToRoot()
{
  return config.checkEncryptionCertificatePathToRoot;
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

void appendDirectoryServer( const char* servername, int port,
                            const char* description )
{
  struct DirectoryServer *servers = NULL;
  servers = xtryrealloc( config.directoryServers,
                         (1+config.numDirectoryServers) * sizeof *servers );
  if( servers ) {
    config.directoryServers = servers;
    servers[ config.numDirectoryServers ].servername  = servername;
    servers[ config.numDirectoryServers ].port        = port;
    servers[ config.numDirectoryServers ].description = description;
    config.numDirectoryServers += 1;
  }
}

void setDirectoryServers( struct DirectoryServer server[], unsigned int size )
{
  struct DirectoryServer *servers = NULL;
  servers = xtrycalloc ( size, sizeof *servers );
  if( servers ) {
    _gpgme_free( config.directoryServers );
    config.directoryServers = servers;
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
/*
  GpgmeCtx ctx;
  GpgmeData data, sig;

  gpgme_new (&ctx);
  gpgme_set_armor (ctx, 1);
  gpgme_set_textmode (ctx, 1);

  gpgme_data_new_from_mem (&data, mime_object,
                            mime_object_len, TRUE );
  gpgme_data_new ( &sig );
  gpgme_op_sign (ctx, data, sig, GPGME_SIG_MODE_DETACH );

  fputs ( "Content-Type: multipart/signed;\r\n"
          "              protocol=\"application/pgp-signature\";\r\n"
          "              boundary=\"42=.42=.42=.42\"\r\n"
          "\r\n--42=.42=.42=.42\r\n", stdout );

  gpgme_data_rewind (data);
  while ( !gpgme_data_read (data, buf, sizeof buf, &nread ) ) {
        fwrite (buf, nread, 1, stdout );
  }
  fputs ( "\r\n--42=.42=.42=.42--\r\n"
          "Content-Type: application/pgp-signature\r\n\r\n", stdout);

  gpgme_data_rewind (sig);
  while ( !gpgme_data_read (sig, buf, sizeof buf, &nread ) ) {
        fwrite (buf, nread, 1, stdout );
  }
  fputs ( "\r\n--42=.42=.42=.42--\r\n", stdout );

  gpgme_release (ctx);
  gpgme_data_release(data);
  gpgme_data_release(sig);
*/
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

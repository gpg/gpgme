/* -*- Mode: C -*-

  $Id$

  CRYPTPLUG - an independent cryptography plug-in API

  Copyright (C) 2001 by Klarälvdalens Datakonsult AB

  CRYPTPLUG is free software; you can redistribute it and/or modify
  it under the terms of GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  CRYPTPLUG is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

#ifndef CRYPTPLUG_H
#define CRYPTPLUG_H

#ifdef __cplusplus
extern "C" {
#else
typedef char bool;
#define true 1
#define false 0
#endif

//#include <stdlib.h>
//#include <string.h>
//#include <ctype.h>


/*! \file cryptplug.h
    \brief Common API header for CRYPTPLUG.

    CRYPTPLUG is an independent cryptography plug-in API
    developed for Sphinx-enabeling KMail and Mutt.

    CRYPTPLUG was designed for the Aegypten project, but it may
    be used by 3rd party developers as well to design pluggable
    crypto backends for the above mentioned MUAs.

    \note All string parameters appearing in this API are to be
    interpreted as UTF-8 encoded.

    \see pgpplugin.c
    \see gpgplugin.c
*/

/*! \defgroup groupGeneral Loading and Unloading the Plugin, General Functionality

    The functions in this section are used for loading and
    unloading plugins. Note that the actual locating of the plugin
    and the loading and unloading of the dynamic library is not
    covered here; this is MUA-specific code for which support code
    might already exist in the programming environments.
*/

/*! \defgroup groupDisplay Graphical Display Functionality

    The functions in this section return stationery that the
    MUAs can use in order to display security functionality
    graphically. This can be toolbar icons, shortcuts, tooltips,
    etc. Not all MUAs will use all this functionality.
*/

/*! \defgroup groupConfig Configuration Support

    The functions in this section provide the necessary
    functionality to configure the security functionality as well
    as to query configuration settings. Since all configuration
    settings will not be saved with the plugin, but rather with
    the MUA, there are also functions to set configuration
    settings programmatically; these will be used on startup of
    the plugin when the MUA transfers the configuration values it
    has read into the plugin. Usually, the functions to query and
    set the configuration values are not needed for anything but
    saving to and restoring from configuration files.
*/


/*! \defgroup groupConfigSign Signature Configuration
    \ingroup groupConfig

    The functions in this section provide the functionality
    to configure signature handling and set and query the
    signature configuration.
*/

/*! \defgroup groupConfigCrypt Encryption Configuration
    \ingroup groupConfig

    The functions in this section provide the functionality
    to configure encryption handling and set and query the
    encryption configuration.

    \note Whenever the term <b> encryption</b> is used here,
    it is supposed to mean both encryption and decryption,
    unless otherwise specified.
*/

/*! \defgroup groupConfigDir Directory Service Configuration
    \ingroup groupConfig

    This section contains messages for configuring the
    directory service.
*/


/*! \defgroup groupCertHand Certificate Handling

    The following methods are used to maintain and query certificates.
*/

/*! \defgroup groupSignAct Signature Actions

    This section describes methods that are used for working
    with signatures.
*/

/*! \defgroup groupCryptAct Encryption and Decryption

    The following methods are used to encrypt and decrypt
    email messages.
*/

/*! \defgroup groupCertAct Certificate Handling Actions

    The functions in this section provide local certificate management.
*/

/*! \defgroup groupCRLAct CRL Handling Actions

    This section describes functions for managing CRLs.
*/





// dummy values:
typedef enum {
  CryptPlugFeat_undef             = 0,

  CryptPlugFeat_SignMessages      = 1,
  CryptPlugFeat_VerifySignatures  = 2,
  CryptPlugFeat_EncryptMessages   = 3,
  CryptPlugFeat_DecryptMessages   = 4   // more to follow ...
} Feature;

// dummy values
typedef enum {
  PinRequest_undef            = 0,

  PinRequest_Always          = 1,
  PinRequest_WhenAddingCerts = 2,
  PinRequest_AlwaysWhenSigning = 3,
  PinRequest_OncePerSession   = 4,
  PinRequest_AfterMinutes     = 5
} PinRequests;

// dummy values:
typedef enum {
  SendCert_undef              = 0,

  SendCert_DontSend           = 1,
  SendCert_SendOwn            = 2,
  SendCert_SendChainWithoutRoot = 3,
  SendCert_SendChainWithRoot  = 4
} SendCertificates;

// dummy values:
typedef enum {
  SignAlg_undef               = 0,

  SignAlg_SHA1                = 1
} SignatureAlgorithm;



typedef enum {
  EncryptAlg_undef            = 0,

  EncryptAlg_RSA              = 1,
  EncryptAlg_SHA1             = 2,
  EncryptAlg_TripleDES        = 3
} EncryptionAlgorithm;

typedef enum {
  SignEmail_undef             = 0,

  SignEmail_SignAll           = 1,
  SignEmail_Ask               = 2,
  SignEmail_DontSign          = 3
} SignEmail;

typedef enum {
  EncryptEmail_undef          = 0,

  EncryptEmail_EncryptAll     = 1,
  EncryptEmail_Ask            = 2,
  EncryptEmail_DontEncrypt    = 3
} EncryptEmail;

typedef enum {
  CertSrc_undef               = 0,

  CertSrc_Server              = 1,
  CertSrc_Local               = 2,
  CertSrc_ServerLocal         = CertSrc_Server | CertSrc_Local
} CertificateSource;






/*! \ingroup groupGeneral
    \brief This function sets up all internal structures.

   Plugins that need no initialization should provide an empty
   implementation. The method returns \c true if the initialization was
   successful and \c false otherwise. Before this function is called,
   no other plugin functions should be called; the behavior is
   undefined in this case.

   \note This function <b>must</b> be implemented by each plug-in using
   this API specification.
*/
bool initialize( void );

/*! \ingroup groupGeneral
    \brief This function frees all internal structures.

    Plugins that do not keep any internal structures should provide an
    empty implementation. After this function has been called,
    no other plugin functions should be called; the behavior is
    undefined in this case.

   \note This function <b>must</b> be implemented by each plug-in using
   this API specification.
*/
void deinitialize( void );

/*! \ingroup groupGeneral
   \brief This function returns \c true if the
          specified feature is available in the plugin, and
          \c false otherwise.

   Not all plugins will support all features; a complete Sphinx
   implementation will support all features contained in the enum,
   however.

   \note This function <b>must</b> be implemented by each plug-in using
   this API specification.
*/
bool hasFeature( Feature );


/*! \ingroup groupDisplay
   \brief Returns stationery to indicate unsafe emails.
*/
void unsafeStationery( void** pixmap, const char** menutext, char* accel,
          const char** tooltip, const char** statusbartext );

/*! \ingroup groupDisplay
   \brief Returns stationery to indicate signed emails.
*/
void signedStationery( void** pixmap, const char** menutext, char* accel,
          const char** tooltip, const char** statusbartext );

/*! \ingroup groupDisplay
   \brief Returns stationery to indicate encrypted emails.
*/
void encryptedStationery( void** pixmap, const char**
          menutext, char* accel,
          const char** tooltip, const char** statusbartext );

/*! \ingroup groupDisplay
   \brief Returns stationery to indicate signed and encrypted emails.
*/
void signedEncryptedStationery( void** pixmap, const char**
          menutext, char* accel,
          const char** tooltip, const char** statusbartext );

/*! \ingroup groupConfigSign
   \brief This function returns an XML representation of a
            configuration dialog for configuring signature
            handling.
            
   The syntax is that of <filename>.ui</filename>
            files as specified in the <emphasis>Imhotep</emphasis>
            documentation. This function does not execute or show the
            dialog in any way; this is up to the MUA. Also, what the
            MUA makes of the information provided highly depends on
            the MUA itself. A GUI-based MUA will probably create a
            dialog window (possibly integrated into an existing
            configuration dialog in the application), while a
            terminal-based MUA might generate a series of questions or
            a terminal based menu selection.
*/
const char* signatureConfigurationDialog( void );

/*! \ingroup groupConfigSign
   \brief This function returns an XML representation of a
            configuration dialog for selecting a signature key.
            
   This will typically be used when the user wants to select a
            signature key for one specific message only; the defaults
            are set in the dialog returned by
            signatureConfigurationDialog().
*/
const char* signatureKeySelectionDialog( void );

/*! \ingroup groupConfigSign
   \brief This function returns an XML representation of a
            configuration dialog for selecting a signature
            algorithm.

   This will typically be used when the user wants
          to select a signature algorithm for one specific message only; the
          defaults are set in the dialog returned by
            signatureConfigurationDialog().
*/
const char* signatureAlgorithmDialog( void );

/*! \ingroup groupConfigSign
   \brief This function returns an XML representation of a
            configuration dialog for selecting whether an email
            message and its attachments should be sent with or
            without signatures.

   This will typically be used when the
            user wants to select a signature key for one specific
            message only; the defaults are set in the dialog returned
            by signatureConfigurationDialog().
*/
const char* signatureHandlingDialog( void );

/*! \ingroup groupConfigSign
   \brief Sets the signature key certificate that identifies the
          role of the signer.
*/
void setSignatureKeyCertificate( const char* certificate );

/*! \ingroup groupConfigSign
   \brief Returns the signature key certificate that identifies
            the role of the signer.
*/
const char* signatureKeyCertificate( void );

/*! \ingroup groupConfigSign
   \brief Sets the algorithm used for signing.
*/
void setSignatureAlgorithm( SignatureAlgorithm );

/*! \ingroup groupConfigSign
   \brief Returns the algorithm used for signing.
*/
SignatureAlgorithm signatureAlgorithm( void );

/*! \ingroup groupConfigSign
   \brief Sets which certificates should be sent with the
            message.
*/
void setSendCertificates( SendCertificates );
/*! \ingroup groupConfigSign
   \brief Returns which certificates should be sent with the
            message.
*/
SendCertificates sendCertificates( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether email should be automatically
            signed, signed after confirmation, signed after
            confirmation for each part or not signed at all.
*/
void setSignEmail( SignEmail );

/*! \ingroup groupConfigSign
   \brief Returns whether email should be automatically
            signed, signed after confirmation, signed after
            confirmation for each part or not signed at all.
*/
SignEmail signEmail( void );

    
/*! \ingroup groupConfigSign
  \brief Specifies whether a warning should be emitted when the user
  tries to send an email message unsigned.
*/
void setWarnSendUnsigned( bool );    

    
/*! \ingroup groupConfigSign
  \brief Returns whether a warning should be emitted when the user
  tries to send an email message unsigned.
*/
bool warnSendUnsigned( void );    
    
    
/*! \ingroup groupConfigSign
   \brief Specifies whether sent email messages should be stored
          with or without their signatures.
*/
void setSaveSentSignatures( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether sent email messages should be stored
            with or without their signatures.
*/
bool saveSentSignatures( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether a warning should be emitted if the
            email address of the sender is not contained in the
            certificate.
*/
void setWarnNoCertificate( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether a warning should be emitted if the
            email address of the sender is not contained in the
            certificate.
*/
bool warnNoCertificate( void );

/*! \ingroup groupConfigSign
   \brief Specifies how often the PIN is requested when
            accessing the secret signature key.
*/
void setNumPINRequests( PinRequests );

/*! \ingroup groupConfigSign
   \brief Returns how often the PIN is requested when
            accessing the secret signature key.
*/
PinRequests numPINRequests( void );

/*! \ingroup groupConfigSign
  \brief Specifies the interval in minutes the PIN must be reentered if
  numPINRequests() is PinRequest_AfterMinutes.
*/
void setNumPINRequestsInterval( int );

    
/*! \ingroup groupConfigSign
  \brief Returns the interval in minutes the PIN must be reentered if
  numPINRequests() is PinRequest_AfterMinutes.
*/
int numPINRequestsInterval( void );


/*! \ingroup groupConfigSign
   \brief Specifies whether the certificate path should be
            followed to the root certificate or whether locally stored
            certificates may be used.
*/
void setCheckSignatureCertificatePathToRoot( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether the certificate path should be
            followed to the root certificate or whether locally stored
            certificates may be used.
*/
bool checkSignatureCertificatePathToRoot( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether certificate revocation lists should
            be used.
*/
void setSignatureUseCRLs( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether certificate revocation lists should
            be used.
*/
bool signatureUseCRLs( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether a warning should be emitted if the
   signature certificate expires in the near future.
*/
void setSignatureCertificateExpiryNearWarning( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether a warning should be emitted if
   the signature certificate expires in the near future.
*/
bool signatureCertificateExpiryNearWarning( void );

/*! \ingroup groupConfigSign
   \brief Specifies the number of days which a signature certificate must
   be valid before it is considered to expire in the near
   future.
*/
void setSignatureCertificateExpiryNearInterval( int );

/*! \ingroup groupConfigSign
   \brief Returns the number of days which a signature certificate must
            be valid before it is considered to expire in the near
            future.
*/
int signatureCertificateExpiryNearInterval( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether a warning should be emitted if the
   CA certificate expires in the near future.
*/
void setCACertificateExpiryNearWarning( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether a warning should be emitted if
   the CA certificate expires in the near future.
*/
bool caCertificateExpiryNearWarning( void );

/*! \ingroup groupConfigSign
   \brief Specifies the number of days which a CA certificate must
   be valid before it is considered to expire in the near
   future.
*/
void setCACertificateExpiryNearInterval( int );

/*! \ingroup groupConfigSign
   \brief Returns the number of days which a CA certificate must
            be valid before it is considered to expire in the near
            future.
*/
int caCertificateExpiryNearInterval( void );

/*! \ingroup groupConfigSign
   \brief Specifies whether a warning should be emitted if the
   root certificate expires in the near future.
*/
void setRootCertificateExpiryNearWarning( bool );

/*! \ingroup groupConfigSign
   \brief Returns whether a warning should be emitted if
   the root certificate expires in the near future.
*/
bool rootCertificateExpiryNearWarning( void );

/*! \ingroup groupConfigSign
   \brief Specifies the number of days which a root certificate must
   be valid before it is considered to expire in the near
   future.
*/
void setRootCertificateExpiryNearInterval( int );

/*! \ingroup groupConfigSign
   \brief Returns the number of days which a signature certificate must
            be valid before it is considered to expire in the near
            future.
*/
int rootCertificateExpiryNearInterval( void );

    
    

/*! \ingroup groupConfigCrypt
   \brief This function returns an XML representation of a
            configuration dialog for configuring encryption
            handling.
            
   The syntax is that of <filename>.ui</filename>
            files as specified in the <emphasis>Imhotep</emphasis>
            documentation. This function does not execute or show the
            dialog in any way; this is up to the MUA. Also, what the
            MUA makes of the information provided highly depends on
            the MUA itself. A GUI-based MUA will probably create a
            dialog window (possibly integrated into an existing
            configuration dialog in the application), while a
            terminal-based MUA might generate a series of questions or
            a terminal based menu selection.
*/
const char* encryptionConfigurationDialog( void );

/*! \ingroup groupConfigCrypt
   \brief This function returns an XML representation of a
            configuration dialog for selecting an encryption
            algorithm.
            
   This will typically be used when the user wants
          to select an encryption algorithm for one specific message only; the
          defaults are set in the dialog returned by
            encryptionConfigurationDialog().
*/
const char* encryptionAlgorithmDialog( void );

/*! \ingroup groupConfigCrypt
   \brief This function returns an XML representation of a
            configuration dialog for selecting whether an email
            message and its attachments should be encrypted.

   This will typically be used when the
            user wants to select an encryption key for one specific
            message only; the defaults are set in the dialog returned
            by encryptionConfigurationDialog().
*/
const char* encryptionHandlingDialog( void );

/*! \ingroup groupConfigCrypt
   \brief This function returns an XML representation of a
            dialog that lets the user select the certificate to use
            for encrypting.
            
   If it was not possible to determine the
            correct certificate from the information in the email
            message, the user is presented with a list of possible
            certificates to choose from. If a unique certificate was
            found, this is presented to the user, who needs to confirm
          the selection of the certificate. This procedure is repeated
          for each recipient of the email message.
*/
const char* encryptionReceiverDialog( void );

/*! \ingroup groupConfigCrypt
   \brief Sets the algorithm used for encrypting.
*/
void setEncryptionAlgorithm( EncryptionAlgorithm );

/*! \ingroup groupConfigCrypt
   \brief Returns the algorithm used for encrypting.
*/
EncryptionAlgorithm encryptionAlgorithm( void );

/*! \ingroup groupConfigCrypt
   \brief Specifies whether email should be automatically
            encrypted, encrypted after confirmation, encrypted after
            confirmation for each part or not encrypted at all.
*/
void setEncryptEmail( EncryptEmail );

/*! \ingroup groupConfigCrypt
   \brief Returns whether email should be automatically
            encrypted, encrypted after confirmation, encrypted after
            confirmation for each part or not encrypted at all.
*/
EncryptEmail encryptEmail( void );

/*! \ingroup groupConfigSign
  \brief Specifies whether a warning should be emitted when the user
  tries to send an email message unencrypted.
*/
void setWarnSendUnencrypted( bool );    

    
/*! \ingroup groupConfigSign
  \brief Returns whether a warning should be emitted when the user
  tries to send an email message unencrypted.
*/
bool warnSendUnencrypted( void );    
    
    
/*! \ingroup groupConfigCrypt
   \brief Specifies whether encrypted email messages should be
            stored encrypted or decrypted.
*/
void setSaveMessagesEncrypted( bool );

/*! \ingroup groupConfigCrypt
   \brief Returns whether encrypted email messages should be stored
            encrypted or decrypted.
*/
bool saveMessagesEncrypted( void );


/*! \ingroup groupConfigCrypt
  \brief Specifies whether the certificate path should be checked
  during encryption.
*/
void setCheckCertificatePath( bool );

/*! \ingroup groupConfigCrypt
  \brief Returns whether the certificate path should be checked
  during encryption.
*/
bool checkCertificatePath( void );

    
/*! \ingroup groupConfigCrypt
   \brief Specifies whether the certificate path should be
            followed to the root certificate or whether locally stored
            certificates may be used.
*/
void setCheckEncryptionCertificatePathToRoot( bool );

/*! \ingroup groupConfigCrypt
   \brief Returns whether the certificate path should be
            followed to the root certificate or whether locally stored
            certificates may be used.
*/
bool checkEncryptionCertificatePathToRoot( void );

    
/*! \ingroup groupConfigCrypt
  \brief Specifies whether a warning should be emitted if the
  certificate of the receiver expires in the near future.
*/
void setReceiverCertificateExpiryNearWarning( bool );

/*! \ingroup groupConfigCrypt
  \brief Returns whether a warning should be emitted if the
  certificate of the receiver expires in the near future.
*/
bool receiverCertificateExpiryNearWarning( void );
    
    
/*! \ingroup groupConfigCrypt
  \brief Specifies the number of days which a receiver certificate
  must be valid before it is considered to expire in the near future.
*/
void setReceiverCertificateExpiryNearWarningInterval( int );
    
/*! \ingroup groupConfigCrypt
  \brief Returns the number of days which a receiver certificate
  must be valid before it is considered to expire in the near future.
*/
int receiverCertificateExpiryNearWarningInterval( void );
    
/*! \ingroup groupConfigCrypt
  \brief Specifies whether a warning should be emitted if 
  a certificate in the chain expires in the near future.
*/
void setCertificateInChainExpiryNearWarning( bool );

    
/*! \ingroup groupConfigCrypt
  \brief Returns whether a warning should be emitted if a
  certificate in the chain expires in the near future.
*/
bool certificateInChainExpiryNearWarning( void );

    
    
/*! \ingroup groupConfigCrypt
  \brief Specifies the number of days which a certificate in the chain
  must be valid before it is considered to expire in the near future.
*/
void setCertificateInChainExpiryNearWarningInterval( int );
    
/*! \ingroup groupConfigCrypt
  \brief Returns the number of days which a certificate in the chain
  must be valid before it is considered to expire in the near future.
*/
int certificateInChainExpiryNearWarningInterval( void );
    
    
/*! \ingroup groupConfigCrypt
  \brief Specifies whether a warning is emitted if the email address
  of the receiver does not appear in the certificate.
*/
void setReceiverEmailAddressNotInCertificateWarning( bool );    

/*! \ingroup groupConfigCrypt
  \brief Returns whether a warning is emitted if the email address
  of the receiver does not appear in the certificate.
*/
bool receiverEmailAddressNotInCertificateWarning( void );    

    
/*! \ingroup groupConfigCrypt
   \brief Specifies whether certificate revocation lists should
            be used.
*/
void setEncryptionUseCRLs( bool );

/*! \ingroup groupConfigCrypt
   \brief Returns whether certificate revocation lists should
            be used.
*/
bool encryptionUseCRLs( void );

/*! \ingroup groupConfigCrypt
   \brief Specifies whether a warning should be emitted if any
            of the certificates involved in the signing process
            expires in the near future.
*/
void setEncryptionCRLExpiryNearWarning( bool );

/*! \ingroup groupConfigCrypt
   \brief Returns whether a warning should be emitted if any
            of the certificates involved in the signing process
            expires in the near future.
*/
bool encryptionCRLExpiryNearWarning( void );

/*! \ingroup groupConfigCrypt
   \brief Specifies the number of days which a certificate must
            be valid before it is considered to expire in the near
            future.
*/
void setEncryptionCRLNearExpiryInterval( int );

/*! \ingroup groupConfigCrypt
   \brief Returns the number of days which a certificate must
            be valid before it is considered to expire in the near
            future.
*/
int encryptionCRLNearExpiryInterval( void );


/*! \ingroup groupConfigDir
   \brief This function returns an XML representation of a
            configuration dialog for selecting a directory
            server.
*/
const char* directoryServiceConfigurationDialog( void );

/*! \ingroup groupConfigDir
   \brief Lets you configure how certificates and certificate
   revocation lists are retrieved (both locally and from directory
   services).

   Will mainly be used for restoring
            configuration data; interactive configuration will be done
            via the configuration dialog returned by
            \c directoryServiceConfigurationDialog().
*/
void appendDirectoryServer( const char* servername, int port,
                            const char* description );




/*! \ingroup groupConfigDir
*/
struct DirectoryServer {
    char* servername;
    int port;
    char* description;
};


/*! \ingroup groupConfigDir
   \brief Specifies a list of directory servers.

   Will mainly be used for restoring
            configuration data; interactive configuration will be done
            via the configuration dialog returned by
            \c directoryServiceConfigurationDialog().
*/
void setDirectoryServers( struct DirectoryServer[], unsigned int size );

/*! \ingroup groupConfigDir
   \brief Returns the list of directory servers.

   Will mainly be used for saving configuration data; interactive
            configuration will be done via the configuration dialog
            returned by
            \c directoryServiceConfigurationDialog().
*/
struct DirectoryServer* directoryServers( int* numServers );

/*! \ingroup groupConfigDir
   \brief Specifies whether certificates should be retrieved
            from a directory server, only locally, or both.
*/
void setCertificateSource( CertificateSource );

/*! \ingroup groupConfigDir
   \brief Returns whether certificates should be retrieved
            from a directory server, only locally, or both.
*/
CertificateSource certificateSource( void );

/*! \ingroup groupConfigDir
   \brief Specifies whether certificates should be retrieved
            from a directory server, only locally, or both.
*/
void setCRLSource( CertificateSource );

/*! \ingroup groupConfigDir
   \brief Returns whether certificates should be retrieved
            from a directory server, only locally, or both.
*/
CertificateSource crlSource( void );


/*! \ingroup groupCertHand
   \brief Returns \c true if and only if the
          certificates in the certificate chain starting at
          \c certificate are valid.
          
   If \c level is non-null, the parameter contains
          the degree of trust on a backend-specific scale. In an X.509
          implementation, this will either be \c 1
          (valid up to the root certificate) or \c 0
          (not valid up to the root certificate).
*/
bool certificateValidity( const char* certificate, int* level );


/*! \ingroup groupSignAct
   \brief Signs a message \c cleartext and returns
          in \c ciphertext the message including
          signature.

   The signature role is specified by
          \c certificate. If \c certificate is \c NULL,
          the default certificate is used.
*/
bool signMessage( const char* cleartext,
                  const char** ciphertext,
                  const char* certificate );


/*! \ingroup groupSignAct
 */
struct SignatureMetaDataExtendedInfo
{
    struct tm* creation_time;
    char* status_text;
    char* fingerprint;
};

/*! \ingroup groupSignAct
*/
struct SignatureMetaData {
    char* status;
    struct SignatureMetaDataExtendedInfo* extended_info;
    int extended_info_count;
    char* nota_xml;
    int status_code;
};

/*! \ingroup groupSignAct
   \brief Checks whether the signature of a message is
          valid. \c ciphertext specifies the signed message
          as it was received by the MUA, \c signaturetext is the
          signature itself.

   Depending on the configuration, MUAs might not need to use this.
   If \c sigmeta is non-null, the
          \c SignatureMetaData object pointed to will
          contain meta information about the signature after the
          function call.
*/
bool checkMessageSignature( const char* ciphertext,
                            const char* signaturetext,
                            struct SignatureMetaData* sigmeta );

/*! \ingroup groupSignAct
   \brief Stores the certificates that follow with the message
          \c ciphertext locally.
*/
bool storeCertificatesFromMessage( const char* ciphertext );


/*! \ingroup groupCryptAct
   \brief Encrypts an email message in
          \c cleartext according to the current
          settings (algorithm, etc.) and returns it in
          \c ciphertext.

   If the message could be encrypted, the function returns
          \c true, otherwise
          \c false.
*/
bool encryptMessage( const char*  cleartext,
                     const char** ciphertext,
                     const char*  addressee );

/*! \ingroup groupCryptAct
   \brief Combines the functionality of
          \c encryptMessage() and
          \c signMessage().

   If \c certificate is \c NULL,
          the default certificate will be used.  If
          \c sigmeta is non-null, the
          \c SignatureMetaData object pointed to will
          contain meta information about the signature after the
          function call.
*/
bool encryptAndSignMessage( const char* cleartext,
                            const char** ciphertext,
                            const char* certificate,
                            struct SignatureMetaData* sigmeta );

/*! \ingroup groupCryptAct
   \brief Tries to decrypt an email message
          \c ciphertext and returns the decrypted
          message in \c cleartext.

   The \c certificate is used for decryption. If
          the message could be decrypted, the function returns
          \c true, otherwise
          \c false.
*/
bool decryptMessage( const char* ciphertext, const
          char** cleartext, const char* certificate );

/*! \ingroup groupCryptAct
   \brief Combines the functionality of
          \c checkMessageSignature() and
          \c decryptMessage().

   If \c certificate is \c NULL,
          the default certificate will be used.  If
          \c sigmeta is non-null, the
          \c SignatureMetaData object pointed to will
          contain meta information about the signature after the
          function call.
*/
bool decryptAndCheckMessage( const char* ciphertext,
                             const char** cleartext,
                             const char* certificate,
                             struct SignatureMetaData* sigmeta );


/*! \ingroup groupCertAct
   \brief This function returns an XML representation of a dialog
          that can be used to fill in the data for requesting a
          certificate (which in turn is done with the function
          \c requestCertificate() described
          next.
*/
const char* requestCertificateDialog( void );

/*! \ingroup groupCertAct
   \brief Generates a prototype certificate with the data provided
        in the first four parameters and sends it via email to the CA
          specified in \c ca_address.
*/
bool requestDecentralCertificate( const char* name, const char*
          email, const char* organization, const char* department,
          const char* ca_address );

/*! \ingroup groupCertAct
   \brief Requests a certificate in a PSE from the CA
          specified in \c ca_address.
*/
bool requestCentralCertificateAndPSE( const char* name,
          const char* email, const char* organization, const char* department,
          const char* ca_address );

/*! \ingroup groupCertAct
   \brief Creates a local PSE.
*/
bool createPSE( void );

/*! \ingroup groupCertAct
   \brief Parses and adds a certificate returned by a CA upon
          request with
          \c requestDecentralCertificate() or
          \c requestCentralCertificate().

   If the certificate was requested with
          \c requestCentralCertificate(), the
          certificate returned will come complete with a PSE which is
          also registered with this method.
*/
bool registerCertificate( const char* );

/*! \ingroup groupCertAct
   \brief Requests the prolongation of the certificate
          \c certificate from the CA
          \c ca_address.
*/
bool requestCertificateProlongation( const char*
          certificate, const char* ca_address );

/*! \ingroup groupCertAct
   \brief Returns an HTML 2-formatted string that describes the
          certificate chain of the user's certificate.
          
   Data displayed is at least the issuer of the certificate, the serial number
        of the certificate, the owner of the certificate, the checksum
        of the certificate, the validity duration of the certificate,
          the usage of the certificate, and the contained email
          addresses, if any.
*/
const char* certificateChain( void );

/*! \ingroup groupCertAct
   \brief Deletes the specified user certificate from the current
          PSE.
*/
bool deleteCertificate( const char* certificate );

/*! \ingroup groupCertAct
   \brief Archives the specified user certificate in the current PSE.

   The certificate cannot be used any longer after this
          operation unless it is unarchived.
*/
bool archiveCertificate( const char* certificate );


/*! \ingroup groupCRLAct
   \brief Returns a HTML 2-formatted string that describes the
          CRL, suitable for display in the MUA.
*/
const char* displayCRL( void );

/*! \ingroup groupCRLAct
   \brief Manually update the CRL. CRLs will also be automatically
        updated on demand by the backend.
        
   If there is a local version of a CRL saved, it will be overwritten
   with the new CRL from the CA.
*/
void updateCRL( void );

#ifdef __cplusplus
}
#endif
#endif /*CRYPTPLUG_H*/


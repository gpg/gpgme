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

#include <stdlib.h>
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


/*! \defgroup groupSignCryptAct Signing and Encrypting Actions

    This section describes methods and structures
    used for signing and/or encrypting your mails.
*/


/*! \defgroup groupSignAct Signature Actions
    \ingroup groupSignCryptAct

    This section describes methods that are used for working
    with signatures.
*/

/*! \defgroup groupCryptAct Encryption and Decryption
    \ingroup groupSignCryptAct

    The following methods are used to encrypt and decrypt
    email messages.
*/

/*! \defgroup groupCertAct Certificate Handling Actions

    The functions in this section provide local certificate management.
*/

/*! \defgroup groupCRLAct CRL Handling Actions

    This section describes functions for managing CRLs.
*/

/*! \defgroup groupAdUsoInterno Important functions to be used by plugin implementors ONLY.

    This section describes functions that have to be used by
    plugin implementors but should not be used by plugin users
    directly.

    If you are not planning to write your own cryptography
    plugin <b>you should ignore this</b> section!
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
    \brief This function returns a URL to be used for reporting a bug that
           you found (or suspect, resp.) in this cryptography plug-in.

   If the plugins for some reason cannot specify an appropriate URL you
   should at least be provided with a text giving you some advise on
   how to report a bug.

   \note This function <b>must</b> be implemented by each plug-in using
   this API specification.
*/
const char* bugURL( void );

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

/*!
  \ingroup groupConfigSign
  \brief Returns true if the specified email address is contained
  in the specified certificate.
*/
bool isEmailInCertificate( const char* email, const char* certificate );

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
      \brief Returns the number of days that are left until the
      specified certificate expires. 
      \param certificate the certificate to check
    */
    int signatureCertificateDaysLeftToExpiry( const char* certificate );

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
      \brief Returns the number of days that are left until the
      CA certificate of the specified certificate expires. 
      \param certificate the certificate to check
    */
    int caCertificateDaysLeftToExpiry( const char* certificate );

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
      \brief Returns the number of days that are left until the
      root certificate of the specified certificate expires. 
      \param certificate the certificate to check
    */
    int rootCertificateDaysLeftToExpiry( const char* certificate );

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


/*! \ingroup groupSignCryptAct
   \brief Information record returned by signing and by encrypting
   functions - this record should be used together with a
   corresponding \c free_StructuringInfo() function call.

   Use this information to compose a MIME object containing signed
   and/or encrypted content (or to build a text frame around your
   flat non-MIME message body, resp.)

   <b>If</b> value returned in \c makeMimeObject is <b>TRUE</b> the
   text strings returned in \c contentTypeMain and \c contentDispMain
   and \c contentTEncMain (and, if required, \c content[..]Version and
   \c bodyTextVersion and \c content[..]Sig) should be used to compose
   a respective MIME object.<br>
   If <b>FALSE</b> the texts returned in \c flatTextPrefix and
   \c flatTextSeparator and \c flatTextPostfix are to be used instead.<br>
   Allways <b>either</b> the \c content[..] and \c bodyTextVersion
   parameters <b>or</b> the \c flatText[..] parameters are holding
   valid data - never both of them may be used simultaneously
   as plugins will just ignore the parameters not matching their
   \c makeMimeObject setting.

   When creating your MIME object please observe these common rules:
   \li Parameters named \c contentType[..] and \c contentDisp[..] and
   \c contentTEnc[..] will return the values for the respective MIME
   headers 'Content-Type' and 'Content-Disposition' and
   'Content-Transfer-Encoding'. The following applies to these parameters:
   \li The relevant MIME part may <b>only</b> be created if the respective
   \c contentType[..] parameter is holding a non-zero-length string. If the
   \c contentType[..] parameter value is invalid or holding an empty string
   the respective \c contentDisp[..] and \c contentTEnc[..] parameters
   should be ignored.
   \li If the respective \c contentDisp[..] or \c contentTEnc[..] parameter
   is NULL or holding a zero-length string it is up to you whether you want
   to add the relevant MIME header yourself, but since it in in the
   responsibility of the plugin implementors to provide you with all
   neccessary 'Content-[..]' header information you should <b>not need</b>
   to define them if they are not returned by the signing or encrypting
   function - otherwise this may be considered as a bug in the plugin and
   you could report the missing MIME header information to the address
   returned by the \c bugURL() function.

   If \c makeMultiMime returns FALSE the \c contentTypeMain returned must
   not be altered but used to specify a single part mime object holding the
   code bloc, e.g. this is used for 'enveloped-data' single part MIME
   objects. In this case you should ignore both the \c content[..]Version
   and \c content[..]Code parameters.

   If \c makeMultiMime returns TRUE also the following rules apply:
   \li If \c includeCleartext is TRUE you should include the cleartext
   as first part of our multipart MIME object, typically this is TRUE
   when signing mails but FALSE when encrypting.
   \li The \c contentTypeMain returned typically starts with
   "multipart/" while providing a "protocol" and a "micalg" parameter: just
   add an appropriate \c "; boundary=[your \c boundary \c string]" to get
   the complete Content-Type value to be used for the MIME object embedding
   both the signed part and the signature part (or - in case of
   encrypting - the version part and the code part, resp.).
   \li If \c contentTypeVersion is holding a non-zero-length string an
   additional MIME part must added immediately before the code part, this
   version part's MIME headers must have the unaltered values of
   \c contentTypeVersion and (if they are holding non-zero-length strings)
   \c contentDispVersion and \c contentTEncVersion, the unaltered contents
   of \c bodyTextVersion must be it's body.
   \li The value returned in \c contentTypeCode is specifying the complete
   Content-Type to be used for this multipart MIME object's signature part
   (or - in case of encrypting - for the code part following after the
   version part, resp.), you should not add/change/remove anything here
   but just use it's unaltered value for specifying the Content-Type header
   of the respective MIME part.
   \li The same applies to the \c contentDispCode value: just use it's
   unaltered value to specify the Content-Disposition header entry of
   the respective MIME part.
   \li The same applies to the \c contentTEncCode value: just use it's
   unaltered value to specify the Content-Transfer-Encoding header of
   the respective MIME part.

   <b>If</b> value returned in \c makeMimeObject is <b>FALSE</b> the
   text strings returned in \c flatTextPrefix and \c flatTextPostfix
   should be used to build a frame around the cleartext and the code
   bloc holding the signature (or - in case of encrypting - the encoded
   data bloc, resp.).<br>
   If \c includeCleartext is TRUE this frame should also include the
   cleartext as first bloc, this bloc should be divided from the code bloc
   by the contents of \c flatTextSeparator - typically this is used for
   signing but not when encrypting.<br>
   If \c includeCleartext is FALSE you should ignore both the cleartext
   and the \c flatTextSeparator parameter.

   <b>How to use StructuringInfo data in your program:</b>
   \li To compose a signed message please act as described below.
   \li For constructing an encrypted message just replace the
   \c signMessage() call by the respective \c encryptMessage() call
   and then proceed exactly the same way.
   \li In any case make <b>sure</b> to free your \c ciphertext <b>and</b>
   to call \c free_StructuringInfo() when you are done with processing
   the data returned by the signing (or encrypting, resp.) function.

\verbatim

    char* ciphertext;
    StructuringInfo structInf;

    if( ! signMessage( cleartext, &ciphertext, certificate,
                       &structuring ) ) {

        myErrorDialog( "Error: could not sign the message!" );

    } else {
      if( structInf.makeMimeObject ) {

        // Build the main MIME object.
        // This is done by
        // using the header values returned in
        // structInf.contentTypeMain and in
        // structInf.contentDispMain and in
        // structInf.contentTEncMain.
        ..

        if( ! structInf.makeMultiMime ) {

          // Build the main MIME object's body.
          // This is done by
          // using the code bloc returned in
          // ciphertext.
          ..

        } else {

          // Build the encapsulated MIME parts.
          if( structInf.includeCleartext ) {

            // Build a MIME part holding the cleartext.
            // This is done by
            // using the original cleartext's headers and by
            // taking it's original body text.
            ..

          }
          if(    structInf.contentTypeVersion
              && 0 < strlen( structInf.contentTypeVersion ) ) {

            // Build a MIME part holding the version information.
            // This is done by
            // using the header values returned in
            // structInf.contentTypeVersion and
            // structInf.contentDispVersion and
            // structInf.contentTEncVersion and by
            // taking the body contents returned in
            // structInf.bodyTextVersion.
            ..

          }
          if(    structInf.contentTypeCode
              && 0 < strlen( structInf.contentTypeCode ) ) {

            // Build a MIME part holding the code information.
            // This is done by
            // using the header values returned in
            // structInf.contentTypeCode and
            // structInf.contentDispCode and
            // structInf.contentTEncCode and by
            // taking the body contents returned in
            // ciphertext.
            ..

          } else {

            // Plugin error!
            myErrorDialog( "Error: Cryptography plugin returned a main"
                           "Content-Type=Multipart/.. but did not "
                           "specify the code bloc's Content-Type header."
                           "\nYou may report this bug:"
                           "\n" + cryptplug.bugURL() );
          }
        }
      } else  {

        // Build a plain message body
        // based on the values returned in structInf.
        // Note: We do _not_ insert line breaks between the parts since
        //       it is the plugin job to provide us with ready-to-use
        //       texts containing all neccessary line breaks.
        strcpy( myMessageBody, structInf.plainTextPrefix );
        if( structInf.includeCleartext ) {
          strcat( myMessageBody, cleartext );
          strcat( myMessageBody, structInf.plainTextSeparator );
        }
        strcat( myMessageBody, *ciphertext );
        strcat( myMessageBody, structInf.plainTextPostfix );
      }

      // free the memory that was allocated
      // for the ciphertext
      free( ciphertext );

      // free the memory that was allocated
      // for our StructuringInfo's char* members
      free_StructuringInfo( &structuring );
    }

\endverbatim

   \note Make sure to call \c free_StructuringInfo() when you are done
   with processing the StructuringInfo data!

  \see free_StructuringInfo
  \see signMessage, encryptMessage, encryptAndSignMessage
*/
struct StructuringInfo {
  bool includeCleartext;     /*!< specifies whether we should include the
                                  cleartext as first part of our multipart
                                  MIME object (or - for non-MIME
                                  messages - as flat text to be set before
                                  the ciphertext, resp.), typically this
                                  is TRUE when signing mails but FALSE
                                  when encrypting<br>
                                  (this parameter is relevant no matter
                                  whether \c makeMimeObject is TRUE or
                                  FALSE) */
  bool  makeMimeObject;      /*!< specifies whether we should create a MIME
                                  object or a flat text message body */
  // the following are used for MIME messages only
  bool  makeMultiMime;       /*!< specifies whether we should create a
                                  'Multipart' MIME object or a single part
                                  object, if FALSE only \c contentTypeMain,
                                  \c contentDispMain and \c contentTEncMain
                                  may be used and all other parameters have
                                  to be ignored<br>
                                  (ignore this parameter if \c makeMimeObject
                                  is FALSE) */
  char* contentTypeMain;     /*!< value of the main 'Content-Type'
                                  header<br>
                                  (ignore this parameter if \c makeMimeObject
                                  is FALSE) */
  char* contentDispMain;     /*!< value of the main 'Content-Disposition'
                                  header<br>
                                  (ignore this parameter if \c makeMimeObject
                                  is FALSE) */
  char* contentTEncMain;     /*!< value of the main
                                  'Content-TransferEncoding' header<br>
                                  (ignore this parameter if \c makeMimeObject
                                  is FALSE) */
  char* contentTypeVersion;  /*!< 'Content-Type' of the additional version
                                  part that might preceed the code part -
                                  if NULL or zero length no version part
                                  must be created<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE) */
  char* contentDispVersion;  /*!< 'Content-Disposition' of the additional
                                  preceeding the code part (only valid if
                                  \c contentTypeVersion holds a
                                  non-zero-length string)<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE or if \c contentTypeVersion does
                                  not return a non-zero-length string) */
  char* contentTEncVersion;  /*!< 'Content-Transfer-Encoding' of the
                                  additional version part (only valid if
                                  \c contentTypeVersion holds a
                                  non-zero-length string)<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE or if \c contentTypeVersion does
                                  not return a non-zero-length string) */
  char* bodyTextVersion;     /*!< body text of the additional version part
                                  (only valid if \c contentTypeVersion
                                  holds a non-zero-length string)<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE or if \c contentTypeVersion does
                                  not return a non-zero-length string) */
  char* contentTypeCode;     /*!< 'Content-Type' of the code part holding
                                  the signature code (or the encrypted
                                  data, resp.)<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE) */
  char* contentDispCode;     /*!< 'Content-Disposition' of the code part<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE or if \c contentTypeCode does
                                  not return a non-zero-length string) */
  char* contentTEncCode;     /*!< 'Content-Type' of the code part<br>
                                  (ignore this parameter if either
                                  \c makeMimeObject or \c makeMultiMime
                                  is FALSE or if \c contentTypeCode does
                                  not return a non-zero-length string) */
  // the following are used for flat non-MIME messages only
  char* flatTextPrefix;      /*!< text to preceed the main text (or the
                                  code bloc containing the encrypted main
                                  text, resp.)<br>
                                  (ignore this parameter if
                                  \c makeMimeObject is TRUE) */
  char* flatTextSeparator;   /*!< text to be put between the main text and
                                  the signature code bloc (not used when
                                  encrypting)<br>
                                  (ignore this parameter if
                                  \c makeMimeObject is TRUE or if
                                  \c includeCleartext is FALSE) */
  char* flatTextPostfix;     /*!< text to follow the signature code bloc
                                  (or the encrypted data bloc, resp.)<br>
                                  (ignore this parameter if
                                  \c makeMimeObject is TRUE) */
};


/*! \ingroup groupAdUsoInterno
    \brief If you are not planning to write your own cryptography
    plugin <b>you should ignore this</b> function!

    Usage of this function is depreciated for plugin users but highly
    recommended for plugin implementors since this is an internal
    function for initializing all char* members of a \c StructuringInfo
    struct.<br>
    This function <b>must</b> be called in <b>any</b> plugin's
    implementations of the following functions:

    \c signMessage() <br>
    \c encryptMessage() <br>
    \c encryptAndSignMessage()

    Calling this function makes sure the corresponding
    \c free_StructuringInfo() calls which will be embedded by
    your plugin's users into their code will be able to
    determine which of the char* members belonging to the
    respective's StructuringInfo had been allocated memory
    for during previous signing or encrypting actions.

    \see free_StructuringInfo, StructuringInfo
    \see signMessage, encryptMessage, encryptAndSignMessage
*/
  void init_StructuringInfo( struct StructuringInfo* s )
  {
    if( ! s ) return;

    s->includeCleartext = false;

    s->makeMimeObject = false;
    s->makeMultiMime = false;

    s->contentTypeMain = 0;
    s->contentDispMain = 0;
    s->contentTEncMain = 0;

    s->contentTypeVersion = 0;
    s->contentDispVersion = 0;
    s->contentTEncVersion = 0;
    s->bodyTextVersion = 0;

    s->contentTypeCode = 0;
    s->contentDispCode = 0;
    s->contentTEncCode = 0;

    s->flatTextPrefix = 0;
    s->flatTextSeparator = 0;
    s->flatTextPostfix = 0;
  }

/*! \ingroup groupSignCryptAct
    \brief Important method for freeing all memory that was allocated
    for the char* members of a \c StructuringInfo struct - use
    this function after <b>each</b> signing or encrypting function
    call.

    \note Even when intending to call \c encryptMessage() immediately
    after having called \c signMessage() you first <b>must</b> call
    the \c free_StructuringInfo() function to make sure all memory is
    set free that was allocated for your StructuringInfo's char* members
    by the \c signMessage() function!

    \see StructuringInfo
*/
  void free_StructuringInfo( struct StructuringInfo* s )
  {
    if( ! s ) return;
    if( s->contentTypeMain )    free( s->contentTypeMain );
    if( s->contentDispMain )    free( s->contentDispMain );
    if( s->contentTEncMain )    free( s->contentTEncMain );
    if( s->contentTypeVersion ) free( s->contentTypeVersion );
    if( s->contentDispVersion ) free( s->contentDispVersion );
    if( s->contentTEncVersion ) free( s->contentTEncVersion );
    if( s->bodyTextVersion )    free( s->bodyTextVersion );
    if( s->contentTypeCode )    free( s->contentTypeCode );
    if( s->contentDispCode )    free( s->contentDispCode );
    if( s->contentTEncCode )    free( s->contentTEncCode );
    if( s->flatTextPrefix )     free( s->flatTextPrefix );
    if( s->flatTextSeparator )  free( s->flatTextSeparator );
    if( s->flatTextPostfix )    free( s->flatTextPostfix );
  }


/*! \ingroup groupSignAct
   \brief Signs a message \c cleartext and returns
          in \c *ciphertext the signature data bloc that
          is to be added to the message.

   The signature role is specified by \c certificate.
   If \c certificate is \c NULL, the default certificate is used.

   If the message could be signed, the function returns
          \c true, otherwise
          \c false.

   Use the StructuringInfo data returned in parameter \c structuring
   to find out how to build the respective MIME object (or the plain
   text message body, resp.).

   \note The function allocates memory for the \c *ciphertext, so
         make sure you set free that memory when no longer needing
         it (as shown in example code provided with documentation
         of the struct \c StructuringInfo).

   \note The function also allocates memory for some char* members
    of the StructuringInfo* parameter that you are providing,
    therefore you <b>must</b> call the \c free_StructuringInfo() function
    to make sure all memory is set free that was allocated. This must be
    done <b>before</b> calling the next cryptography function - even if
    you intend to call \c encryptMessage() immediately after
    \c signMessage().

   \see StructuringInfo, free_StructuringInfo
*/
bool signMessage( const char*  cleartext,
                  const char** ciphertext,
                  const char*  certificate,
                  struct StructuringInfo* structuring );


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
          \c cleartext according to the \c addressee and
          the current settings (algorithm, etc.) and
          returns the encoded data bloc in \c *ciphertext.

   If the message could be encrypted, the function returns
          \c true, otherwise
          \c false.

   Use the StructuringInfo data returned in parameter \c structuring
   to find out how to build the respective MIME object (or the plain
   text message body, resp.).

   \note The function allocates memory for the \c *ciphertext, so
         make sure you set free that memory when no longer needing
         it (as shown in example code provided with documentation
         of the struct \c StructuringInfo).

   \note The function also allocates memory for some char* members
    of the StructuringInfo* parameter that you are providing,
    therefore you <b>must</b> call the \c free_StructuringInfo() function
    to make sure all memory is set free that was allocated. This must be
    done <b>before</b> calling the next cryptography function!

   \see StructuringInfo, free_StructuringInfo
*/
bool encryptMessage( const char*  cleartext,
                     const char** ciphertext,
                     const char*  addressee,
                     struct StructuringInfo* structuring );


/*! \ingroup groupCryptAct
   \brief Combines the functionality of
          \c encryptMessage() and
          \c signMessage().

   If \c certificate is \c NULL,
   the default certificate will be used.

   If the message could be signed and encrypted, the function returns
          \c true, otherwise
          \c false.

   Use the StructuringInfo data returned in parameter \c structuring
   to find out how to build the respective MIME object (or the plain
   text message body, resp.).

   \note The function allocates memory for the \c *ciphertext, so
         make sure you set free that memory when no longer needing
         it (as shown in example code provided with documentation
         of the struct \c StructuringInfo).

   \note The function also allocates memory for some char* members
    of the StructuringInfo* parameter that you are providing,
    therefore you <b>must</b> call the \c free_StructuringInfo() function
    to make sure all memory is set free that was allocated. This must be
    done <b>before</b> calling the next cryptography function!

   \see StructuringInfo, free_StructuringInfo
*/
bool encryptAndSignMessage( const char* cleartext,
                            const char** ciphertext,
                            const char* certificate,
                            struct StructuringInfo* structuring );

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
   the default certificate will be used.
   If \c sigmeta is non-null, the \c SignatureMetaData
   object pointed to will contain meta information about
   the signature after the function call.
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


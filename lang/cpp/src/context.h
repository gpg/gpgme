/*
  context.h - wraps a gpgme key context
  Copyright (C) 2003, 2007 Klarälvdalens Datakonsult AB

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

// -*- c++ -*-
#ifndef __GPGMEPP_CONTEXT_H__
#define __GPGMEPP_CONTEXT_H__

#include "global.h"

#include "error.h"
#include "verificationresult.h" // for Signature::Notation

#include <memory>
#include <vector>
#include <utility>
#include <iosfwd>

namespace GpgME
{

class Key;
class Data;
class TrustItem;
class ProgressProvider;
class PassphraseProvider;
class EventLoopInteractor;
class EditInteractor;
class AssuanTransaction;

class AssuanResult;
class KeyListResult;
class KeyGenerationResult;
class ImportResult;
class DecryptionResult;
class VerificationResult;
class SigningResult;
class EncryptionResult;
class VfsMountResult;

class EngineInfo;

class GPGMEPP_EXPORT Context
{
    explicit Context(gpgme_ctx_t);
public:
    //using GpgME::Protocol;

    //
    // Creation and destruction:
    //

    static Context *createForProtocol(Protocol proto);
    static std::auto_ptr<Context> createForEngine(Engine engine, Error *err = 0);
    virtual ~Context();

    //
    // Context Attributes
    //

    Protocol protocol() const;

    void setArmor(bool useArmor);
    bool armor() const;

    void setTextMode(bool useTextMode);
    bool textMode() const;

    void setOffline(bool useOfflineMode);
    bool offline() const;

    enum CertificateInclusion {
        DefaultCertificates = -256,
        AllCertificatesExceptRoot = -2,
        AllCertificates = -1,
        NoCertificates = 0,
        OnlySenderCertificate = 1
    };
    void setIncludeCertificates(int which);
    int includeCertificates() const;

    //using GpgME::KeyListMode;
    void setKeyListMode(unsigned int keyListMode);
    void addKeyListMode(unsigned int keyListMode);
    unsigned int keyListMode() const;

    void setPassphraseProvider(PassphraseProvider *provider);
    PassphraseProvider *passphraseProvider() const;

    void setProgressProvider(ProgressProvider *provider);
    ProgressProvider *progressProvider() const;

    void setManagedByEventLoopInteractor(bool managed);
    bool managedByEventLoopInteractor() const;

    GpgME::Error setLocale(int category, const char *value);

    EngineInfo engineInfo() const;
    GpgME::Error setEngineFileName(const char *filename);
    GpgME::Error setEngineHomeDirectory(const char *filename);

private:
    friend class ::GpgME::EventLoopInteractor;
    void installIOCallbacks(gpgme_io_cbs *iocbs);
    void uninstallIOCallbacks();

public:
    //
    //
    // Key Management
    //
    //

    //
    // Key Listing
    //

    GpgME::Error startKeyListing(const char *pattern = 0, bool secretOnly = false);
    GpgME::Error startKeyListing(const char *patterns[], bool secretOnly = false);

    Key nextKey(GpgME::Error &e);

    KeyListResult endKeyListing();
    KeyListResult keyListResult() const;

    Key key(const char *fingerprint, GpgME::Error &e, bool secret = false);

    //
    // Key Generation
    //

    KeyGenerationResult generateKey(const char *parameters, Data &pubKey);
    GpgME::Error startKeyGeneration(const char *parameters, Data &pubkey);
    KeyGenerationResult keyGenerationResult() const;

    //
    // Key Export
    //

    GpgME::Error exportPublicKeys(const char *pattern, Data &keyData);
    GpgME::Error exportPublicKeys(const char *pattern[], Data &keyData);
    GpgME::Error startPublicKeyExport(const char *pattern, Data &keyData);
    GpgME::Error startPublicKeyExport(const char *pattern[], Data &keyData);

    //
    // Key Import
    //

    ImportResult importKeys(const Data &data);
    ImportResult importKeys(const std::vector<Key> &keys);
    GpgME::Error startKeyImport(const Data &data);
    GpgME::Error startKeyImport(const std::vector<Key> &keys);
    ImportResult importResult() const;

    //
    // Key Deletion
    //

    GpgME::Error deleteKey(const Key &key, bool allowSecretKeyDeletion = false);
    GpgME::Error startKeyDeletion(const Key &key, bool allowSecretKeyDeletion = false);

    //
    // Passphrase changing
    //

    GpgME::Error passwd(const Key &key);
    GpgME::Error startPasswd(const Key &key);

    //
    // Key Editing
    //

    GpgME::Error edit(const Key &key, std::auto_ptr<EditInteractor> function, Data &out);
    GpgME::Error startEditing(const Key &key, std::auto_ptr<EditInteractor> function, Data &out);

    EditInteractor *lastEditInteractor() const;
    std::auto_ptr<EditInteractor> takeLastEditInteractor();

    //
    // SmartCard Editing
    //

    GpgME::Error cardEdit(const Key &key, std::auto_ptr<EditInteractor> function, Data &out);
    GpgME::Error startCardEditing(const Key &key, std::auto_ptr<EditInteractor> function, Data &out);

    EditInteractor *lastCardEditInteractor() const;
    std::auto_ptr<EditInteractor> takeLastCardEditInteractor();

    //
    // Trust Item Management
    //

    GpgME::Error startTrustItemListing(const char *pattern, int maxLevel);
    TrustItem nextTrustItem(GpgME::Error &e);
    GpgME::Error endTrustItemListing();

    //
    // Assuan Transactions
    //

    AssuanResult assuanTransact(const char *command, std::auto_ptr<AssuanTransaction> transaction);
    AssuanResult assuanTransact(const char *command);
    GpgME::Error startAssuanTransaction(const char *command, std::auto_ptr<AssuanTransaction> transaction);
    GpgME::Error startAssuanTransaction(const char *command);
    AssuanResult assuanResult() const;

    AssuanTransaction *lastAssuanTransaction() const;
    std::auto_ptr<AssuanTransaction> takeLastAssuanTransaction();

    //
    //
    // Crypto Operations
    //
    //

    //
    // Decryption
    //

    DecryptionResult decrypt(const Data &cipherText, Data &plainText);
    GpgME::Error startDecryption(const Data &cipherText, Data &plainText);
    DecryptionResult decryptionResult() const;

    //
    // Signature Verification
    //

    VerificationResult verifyDetachedSignature(const Data &signature, const Data &signedText);
    VerificationResult verifyOpaqueSignature(const Data &signedData, Data &plainText);
    GpgME::Error startDetachedSignatureVerification(const Data &signature, const Data &signedText);
    GpgME::Error startOpaqueSignatureVerification(const Data &signedData, Data &plainText);
    VerificationResult verificationResult() const;

    //
    // Combined Decryption and Signature Verification
    //

    std::pair<DecryptionResult, VerificationResult> decryptAndVerify(const Data &cipherText, Data &plainText);
    GpgME::Error startCombinedDecryptionAndVerification(const Data &cipherText, Data &plainText);
    // use verificationResult() and decryptionResult() to retrieve the result objects...

    //
    // Signing
    //

    void clearSigningKeys();
    GpgME::Error addSigningKey(const Key &signer);
    Key signingKey(unsigned int index) const;
    std::vector<Key> signingKeys() const;

    void clearSignatureNotations();
    GpgME::Error addSignatureNotation(const char *name, const char *value, unsigned int flags = 0);
    GpgME::Error addSignaturePolicyURL(const char *url, bool critical = false);
    const char *signaturePolicyURL() const;
    Notation signatureNotation(unsigned int index) const;
    std::vector<Notation> signatureNotations() const;

    //using GpgME::SignatureMode;
    SigningResult sign(const Data &plainText, Data &signature, SignatureMode mode);
    GpgME::Error startSigning(const Data &plainText, Data &signature, SignatureMode mode);
    SigningResult signingResult() const;

    //
    // Encryption
    //

    enum EncryptionFlags { None = 0, AlwaysTrust = 1, NoEncryptTo = 2 };
    EncryptionResult encrypt(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags);
    GpgME::Error encryptSymmetrically(const Data &plainText, Data &cipherText);
    GpgME::Error startEncryption(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags);
    EncryptionResult encryptionResult() const;

    //
    // Combined Signing and Encryption
    //

    std::pair<SigningResult, EncryptionResult> signAndEncrypt(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags);
    GpgME::Error startCombinedSigningAndEncryption(const std::vector<Key> &recipients, const Data &plainText, Data &cipherText, EncryptionFlags flags);
    // use encryptionResult() and signingResult() to retrieve the result objects...

    //
    //
    // Audit Log
    //
    //
    enum AuditLogFlags {
        HtmlAuditLog = 1,
        AuditLogWithHelp = 128
    };
    GpgME::Error startGetAuditLog(Data &output, unsigned int flags = 0);
    GpgME::Error getAuditLog(Data &output, unsigned int flags = 0);

    //
    //
    // G13 crypto container operations
    //
    //
    GpgME::Error createVFS(const char *containerFile, const std::vector<Key> &recipients);
    VfsMountResult mountVFS(const char *containerFile, const char *mountDir);

    //
    //
    // Run Control
    //
    //

    bool poll();
    GpgME::Error wait();
    GpgME::Error lastError() const;
    GpgME::Error cancelPendingOperation();

    class Private;
    const Private *impl() const
    {
        return d;
    }
    Private *impl()
    {
        return d;
    }
private:
    Private *const d;

private: // disable...
    Context(const Context &);
    const Context &operator=(const Context &);
};

GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Context::CertificateInclusion incl);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Context::EncryptionFlags flags);
GPGMEPP_EXPORT std::ostream &operator<<(std::ostream &os, Context::AuditLogFlags flags);

} // namespace GpgME

#endif // __GPGMEPP_CONTEXT_H__

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
#include "key.h"
#include "verificationresult.h" // for Signature::Notation

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <iosfwd>

namespace GpgME
{

class Data;
class TrustItem;
class ProgressProvider;
class PassphraseProvider;
class EventLoopInteractor;
class EditInteractor;
class AssuanTransaction;

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
    /** Same as above but returning a unique ptr. */
    static std::unique_ptr<Context> create(Protocol proto);
    static std::unique_ptr<Context> createForEngine(Engine engine, Error *err = nullptr);
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

    const char *getFlag(const char *name) const;
    Error setFlag(const char *name, const char *value);

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

    /** Set the passphrase provider
     *
     * To avoid problems where a class using a context registers
     * itself as the provider the Context does not take ownership
     * of the provider and the caller must ensure that the provider
     * is deleted if it is no longer needed.
     */
    void setPassphraseProvider(PassphraseProvider *provider);
    PassphraseProvider *passphraseProvider() const;

    /** Set the progress provider
     *
     * To avoid problems where a class using a context registers
     * itself as the provider the Context does not take ownership
     * of the provider and the caller must ensure that the provider
     * is deleted if it is no longer needed.
     */
    void setProgressProvider(ProgressProvider *provider);
    ProgressProvider *progressProvider() const;

    void setManagedByEventLoopInteractor(bool managed);
    bool managedByEventLoopInteractor() const;

    GpgME::Error setLocale(int category, const char *value);

    EngineInfo engineInfo() const;
    GpgME::Error setEngineFileName(const char *filename);
    GpgME::Error setEngineHomeDirectory(const char *filename);

    enum PinentryMode{
        PinentryDefault = 0,
        PinentryAsk = 1,
        PinentryCancel = 2,
        PinentryError = 3,
        PinentryLoopback = 4
    };
    GpgME::Error setPinentryMode(PinentryMode which);
    PinentryMode pinentryMode() const;

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

    GpgME::Error startKeyListing(const char *pattern = nullptr, bool secretOnly = false);
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
    enum ExportMode {
        ExportDefault = 0,
        ExportExtern = 2,
        ExportMinimal = 4,
        ExportSecret = 16,
        ExportRaw = 32,
        ExportPKCS12 = 64,
        ExportNoUID = 128, // obsolete; has no effect
        ExportSSH = 256,
        ExportSecretSubkey = 512,
    };

    GpgME::Error exportPublicKeys(const char *pattern, Data &keyData);
    GpgME::Error exportPublicKeys(const char *pattern, Data &keyData, unsigned int mode);
    GpgME::Error exportPublicKeys(const char *pattern[], Data &keyData);
    GpgME::Error exportPublicKeys(const char *pattern[], Data &keyData, unsigned int mode);
    GpgME::Error startPublicKeyExport(const char *pattern, Data &keyData);
    GpgME::Error startPublicKeyExport(const char *pattern, Data &keyData, unsigned int mode);
    GpgME::Error startPublicKeyExport(const char *pattern[], Data &keyData);
    GpgME::Error startPublicKeyExport(const char *pattern[], Data &keyData, unsigned int mode);

    GpgME::Error exportSecretKeys(const char *pattern, Data &keyData, unsigned int mode = ExportSecret);
    GpgME::Error exportSecretKeys(const char *pattern[], Data &keyData, unsigned int mode = ExportSecret);
    GpgME::Error startSecretKeyExport(const char *pattern, Data &keyData, unsigned int mode = ExportSecret);
    GpgME::Error startSecretKeyExport(const char *pattern[], Data &keyData, unsigned int mode = ExportSecret);

    GpgME::Error exportSecretSubkeys(const char *pattern, Data &keyData, unsigned int mode = ExportSecretSubkey);
    GpgME::Error exportSecretSubkeys(const char *pattern[], Data &keyData, unsigned int mode = ExportSecretSubkey);
    GpgME::Error startSecretSubkeyExport(const char *pattern, Data &keyData, unsigned int mode = ExportSecretSubkey);
    GpgME::Error startSecretSubkeyExport(const char *pattern[], Data &keyData, unsigned int mode = ExportSecretSubkey);

    // generic export functions; prefer using the specific public/secret key export functions
    GpgME::Error exportKeys(const char *pattern, Data &keyData, unsigned int mode = ExportDefault);
    GpgME::Error exportKeys(const char *pattern[], Data &keyData, unsigned int mode = ExportDefault);
    GpgME::Error startKeyExport(const char *pattern, Data &keyData, unsigned int mode = ExportDefault);
    GpgME::Error startKeyExport(const char *pattern[], Data &keyData, unsigned int mode = ExportDefault);

    //
    // Key Import
    //

    ImportResult importKeys(const Data &data);
    ImportResult importKeys(const std::vector<Key> &keys);
    ImportResult importKeys(const std::vector<std::string> &keyIds);
    GpgME::Error startKeyImport(const Data &data);
    GpgME::Error startKeyImport(const std::vector<Key> &keys);
    GpgME::Error startKeyImport(const std::vector<std::string> &keyIds);
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

    GpgME::Error edit(const Key &key, std::unique_ptr<EditInteractor> function, Data &out);
    GpgME::Error startEditing(const Key &key, std::unique_ptr<EditInteractor> function, Data &out);


    //
    // Modern Interface actions. Require 2.1.x
    //
    Error startCreateKey (const char *userid,
                          const char *algo,
                          unsigned long reserved,
                          unsigned long expires,
                          const Key &certkey,
                          unsigned int flags);
    Error createKey (const char *userid,
                     const char *algo,
                     unsigned long reserved,
                     unsigned long expires,
                     const Key &certkey,
                     unsigned int flags);

    // Same as create key but returning a result
    GpgME::KeyGenerationResult createKeyEx (const char *userid,
                                            const char *algo,
                                            unsigned long reserved,
                                            unsigned long expires,
                                            const Key &certkey,
                                            unsigned int flags);

    Error addUid(const Key &key, const char *userid);
    Error startAddUid(const Key &key, const char *userid);

    Error revUid(const Key &key, const char *userid);
    Error startRevUid(const Key &key, const char *userid);

    Error createSubkey(const Key &key, const char *algo,
                       unsigned long reserved = 0,
                       unsigned long expires = 0,
                       unsigned int flags = 0);
    Error startCreateSubkey(const Key &key, const char *algo,
                            unsigned long reserved = 0,
                            unsigned long expires = 0,
                            unsigned int flags = 0);

    enum SetExpireFlags {
        SetExpireDefault = 0,
        SetExpireAllSubkeys = 1
    };

    Error setExpire(const Key &k, unsigned long expires,
                    const std::vector<Subkey> &subkeys = std::vector<Subkey>(),
                    const SetExpireFlags flags = SetExpireDefault);
    Error startSetExpire(const Key &k, unsigned long expires,
                         const std::vector<Subkey> &subkeys = std::vector<Subkey>(),
                         const SetExpireFlags flags = SetExpireDefault);

    Error revokeSignature(const Key &key, const Key &signingKey,
                          const std::vector<UserID> &userIds = std::vector<UserID>());
    Error startRevokeSignature(const Key &key, const Key &signingKey,
                               const std::vector<UserID> &userIds = std::vector<UserID>());

    // using TofuInfo::Policy
    Error setTofuPolicy(const Key &k, unsigned int policy);
    Error setTofuPolicyStart(const Key &k, unsigned int policy);

    EditInteractor *lastEditInteractor() const;
    std::unique_ptr<EditInteractor> takeLastEditInteractor();

    //
    // SmartCard Editing
    //

    GpgME::Error cardEdit(const Key &key, std::unique_ptr<EditInteractor> function, Data &out);
    GpgME::Error startCardEditing(const Key &key, std::unique_ptr<EditInteractor> function, Data &out);

    EditInteractor *lastCardEditInteractor() const;
    std::unique_ptr<EditInteractor> takeLastCardEditInteractor();

    //
    // Trust Item Management
    //

    GpgME::Error startTrustItemListing(const char *pattern, int maxLevel);
    TrustItem nextTrustItem(GpgME::Error &e);
    GpgME::Error endTrustItemListing();

    //
    // Assuan Transactions
    //

    GpgME::Error assuanTransact(const char *command, std::unique_ptr<AssuanTransaction> transaction);
    GpgME::Error assuanTransact(const char *command);
    GpgME::Error startAssuanTransaction(const char *command, std::unique_ptr<AssuanTransaction> transaction);
    GpgME::Error startAssuanTransaction(const char *command);

    AssuanTransaction *lastAssuanTransaction() const;
    std::unique_ptr<AssuanTransaction> takeLastAssuanTransaction();

    //
    //
    // Crypto Operations
    //

    enum DecryptionFlags {
        // Keep in line with core's flags
        DecryptNone = 0,
        DecryptVerify = 1,
        DecryptUnwrap = 128,
        DecryptMaxValue = 0x80000000
    };

    //
    // Decryption
    //

    // Alternative way to set decryption flags as they were added only in
    // 1.9.0 and so other API can still be used but with 1.9.0 additionally
    // flags can be set.
    void setDecryptionFlags (const DecryptionFlags flags);

    DecryptionResult decrypt(const Data &cipherText, Data &plainText);
    GpgME::Error startDecryption(const Data &cipherText, Data &plainText);
    DecryptionResult decrypt(const Data &cipherText, Data &plainText, const DecryptionFlags flags);
    GpgME::Error startDecryption(const Data &cipherText, Data &plainText, const DecryptionFlags flags);
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
    std::pair<DecryptionResult, VerificationResult> decryptAndVerify(const Data &cipherText, Data &plainText, const DecryptionFlags flags);
    GpgME::Error startCombinedDecryptionAndVerification(const Data &cipherText, Data &plainText);
    GpgME::Error startCombinedDecryptionAndVerification(const Data &cipherText, Data &plainText, const DecryptionFlags flags);
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

    // wrapper for gpgme_set_sender
    const char *getSender();
    GpgME::Error setSender(const char *sender);

    //
    // Encryption
    //

    enum EncryptionFlags {
        None = 0,
        AlwaysTrust = 1,
        NoEncryptTo = 2,
        Prepare = 4,
        ExpectSign = 8,
        NoCompress = 16,
        Symmetric = 32,
        ThrowKeyIds = 64,
        EncryptWrap = 128
    };
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
        DefaultAuditLog = 0,
        HtmlAuditLog = 1,
        DiagnosticAuditLog = 2,
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

    // Spawn Engine
    enum SpawnFlags {
        SpawnNone = 0,
        SpawnDetached = 1,
        SpawnAllowSetFg = 2,
        SpawnShowWindow = 4
    };
    /** Spwan the process \a file with arguments \a argv.
     *
     *  If a data parameter is null the /dev/null will be
     *  used. (Or other platform stuff).
     *
     * @param file The executable to start.
     * @param argv list of arguments file should be argv[0].
     * @param input The data to be sent through stdin.
     * @param output The data to be receive the stdout.
     * @param err The data to receive stderr.
     * @param flags Additional flags.
     *
     * @returns An error or empty error.
     */
    GpgME::Error spawn(const char *file, const char *argv[],
                       Data &input, Data &output, Data &err,
                       SpawnFlags flags);
    /** Async variant of spawn. Immediately returns after starting the
     * process. */
    GpgME::Error spawnAsync(const char *file, const char *argv[],
                            Data &input, Data &output,
                            Data &err, SpawnFlags flags);
    //
    //
    // Run Control
    //
    //

    bool poll();
    GpgME::Error wait();
    GpgME::Error lastError() const;
    GpgME::Error cancelPendingOperation();
    GpgME::Error cancelPendingOperationImmediately();

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
    // Helper functions that need to be context because they rely
    // on the "Friendlyness" of context to access the gpgme types.
    gpgme_key_t *getKeysFromRecipients(const std::vector<Key> &recipients);

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

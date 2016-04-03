/*
    qgpgmebackend.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2005 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    In addition, as a special exception, the copyright holders give
    permission to link the code of this program with any edition of
    the Qt library by Trolltech AS, Norway (or with modified versions
    of Qt that use the same license as Qt), and distribute linked
    combinations including the two.  You must obey the GNU General
    Public License in all respects for all of the code used other than
    Qt.  If you modify this file, you may extend this exception to
    your version of the file, but you are not obligated to do so.  If
    you do not wish to do so, delete this exception statement from
    your version.
*/

#ifndef __QGPGME_QGPGMEBACKEND_H__
#define __QGPGME_QGPGMEBACKEND_H__

#include <QString>

namespace QGpgME
{
class CryptoConfig;
class KeyListJob;
class ListAllKeysJob;
class KeyGenerationJob;
class ImportJob;
class ImportFromKeyserverJob;
class ExportJob;
class DownloadJob;
class DeleteJob;
class EncryptJob;
class DecryptJob;
class SignJob;
class SignKeyJob;
class VerifyDetachedJob;
class VerifyOpaqueJob;
class SignEncryptJob;
class DecryptVerifyJob;
class RefreshKeysJob;
class ChangeExpiryJob;
class ChangeOwnerTrustJob;
class ChangePasswdJob;
class AddUserIDJob;
class SpecialJob;
}

class QString;
class QVariant;
template <typename T_Key, typename T_Value> class QMap;

namespace QGpgME
{
class CryptoConfig;
class Protocol;

class QGpgMEBackend
{
public:
    QGpgMEBackend();
    ~QGpgMEBackend();

    QString name() const;
    QString displayName() const;

    CryptoConfig *config() const;

    Protocol *openpgp() const;
    Protocol *smime() const;
    Protocol *protocol(const char *name) const;

    static const char OpenPGP[];
    static const char SMIME[];

    bool checkForOpenPGP(QString *reason = Q_NULLPTR) const;
    bool checkForSMIME(QString *reason = Q_NULLPTR) const;
    bool checkForProtocol(const char *name, QString *reason) const;

    bool supportsOpenPGP() const
    {
        return true;
    }
    bool supportsSMIME() const
    {
        return true;
    }
    bool supportsProtocol(const char *name) const;

    const char *enumerateProtocols(int i) const;

private:
    mutable QGpgME::CryptoConfig *mCryptoConfig;
    mutable Protocol *mOpenPGPProtocol;
    mutable Protocol *mSMIMEProtocol;
};

class Protocol
{
public:
    virtual ~Protocol() {}

    virtual QString name() const = 0;

    virtual QString displayName() const = 0;

    virtual KeyListJob           *keyListJob(bool remote = false, bool includeSigs = false, bool validate = false) const = 0;
    virtual ListAllKeysJob       *listAllKeysJob(bool includeSigs = false, bool validate = false) const = 0;
    virtual EncryptJob           *encryptJob(bool armor = false, bool textmode = false) const = 0;
    virtual DecryptJob           *decryptJob() const = 0;
    virtual SignJob              *signJob(bool armor = false, bool textMode = false) const = 0;
    virtual VerifyDetachedJob    *verifyDetachedJob(bool textmode = false) const = 0;
    virtual VerifyOpaqueJob      *verifyOpaqueJob(bool textmode = false) const = 0;
    virtual KeyGenerationJob     *keyGenerationJob() const = 0;
    virtual ImportJob            *importJob() const = 0;
    virtual ImportFromKeyserverJob *importFromKeyserverJob() const = 0;
    virtual ExportJob            *publicKeyExportJob(bool armor = false) const = 0;
    // @param charset the encoding of the passphrase in the exported file
    virtual ExportJob            *secretKeyExportJob(bool armor = false, const QString &charset = QString()) const = 0;
    virtual DownloadJob          *downloadJob(bool armor = false) const = 0;
    virtual DeleteJob            *deleteJob() const = 0;
    virtual SignEncryptJob       *signEncryptJob(bool armor = false, bool textMode = false) const = 0;
    virtual DecryptVerifyJob     *decryptVerifyJob(bool textmode = false) const = 0;
    virtual RefreshKeysJob       *refreshKeysJob() const = 0;
    virtual ChangeExpiryJob      *changeExpiryJob() const = 0;
    virtual SignKeyJob           *signKeyJob() const = 0;
    virtual ChangePasswdJob      *changePasswdJob() const = 0;
    virtual ChangeOwnerTrustJob  *changeOwnerTrustJob() const = 0;
    virtual AddUserIDJob         *addUserIDJob() const = 0;
    virtual SpecialJob           *specialJob(const char *type, const QMap<QString, QVariant> &args) const = 0;
};

}

#endif // __QGPGME_QGPGMEBACKEND_H__

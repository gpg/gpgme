/*
    protocol_p.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2005 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
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
#ifndef __QGPGME_PROTOCOL_P_H__
#define __QGPGME_PROTOCOL_P_H__
#include "qgpgmenewcryptoconfig.h"

#include "qgpgmekeygenerationjob.h"
#include "qgpgmekeylistjob.h"
#include "qgpgmelistallkeysjob.h"
#include "qgpgmedecryptjob.h"
#include "qgpgmedecryptverifyjob.h"
#include "qgpgmerefreshkeysjob.h"
#include "qgpgmedeletejob.h"
#include "qgpgmesecretkeyexportjob.h"
#include "qgpgmedownloadjob.h"
#include "qgpgmesignencryptjob.h"
#include "qgpgmeencryptjob.h"
#include "qgpgmesignjob.h"
#include "qgpgmesignkeyjob.h"
#include "qgpgmeexportjob.h"
#include "qgpgmeverifydetachedjob.h"
#include "qgpgmeimportjob.h"
#include "qgpgmeimportfromkeyserverjob.h"
#include "qgpgmeverifyopaquejob.h"
#include "qgpgmechangeexpiryjob.h"
#include "qgpgmechangeownertrustjob.h"
#include "qgpgmechangepasswdjob.h"
#include "qgpgmeadduseridjob.h"
#include "qgpgmekeyformailboxjob.h"
#include "qgpgmewkspublishjob.h"
#include "qgpgmetofupolicyjob.h"
#include "qgpgmequickjob.h"

namespace
{

class Protocol : public QGpgME::Protocol
{
    GpgME::Protocol mProtocol;
public:
    explicit Protocol(GpgME::Protocol proto) : mProtocol(proto) {}

    QString name() const Q_DECL_OVERRIDE
    {
        switch (mProtocol) {
        case GpgME::OpenPGP: return QStringLiteral("OpenPGP");
        case GpgME::CMS:     return QStringLiteral("SMIME");
        default:             return QString();
        }
    }

    QString displayName() const Q_DECL_OVERRIDE
    {
        // ah (2.4.16): Where is this used and isn't this inverted
        // with name
        switch (mProtocol) {
        case GpgME::OpenPGP: return QStringLiteral("gpg");
        case GpgME::CMS:     return QStringLiteral("gpgsm");
        default:             return QStringLiteral("unknown");
        }
    }

    QGpgME::SpecialJob *specialJob(const char *, const QMap<QString, QVariant> &) const Q_DECL_OVERRIDE
    {
        return nullptr;
    }

    QGpgME::KeyListJob *keyListJob(bool remote, bool includeSigs, bool validate) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        unsigned int mode = context->keyListMode();
        if (remote) {
            mode |= GpgME::Extern;
            mode &= ~GpgME::Local;
        } else {
            mode |= GpgME::Local;
            mode &= ~GpgME::Extern;
        }
        if (includeSigs) {
            mode |= GpgME::Signatures;
        }
        if (validate) {
            mode |= GpgME::Validate;
        }
        context->setKeyListMode(mode);
        return new QGpgME::QGpgMEKeyListJob(context);
    }

    QGpgME::ListAllKeysJob *listAllKeysJob(bool includeSigs, bool validate) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        unsigned int mode = context->keyListMode();
        mode |= GpgME::Local;
        mode &= ~GpgME::Extern;
        if (includeSigs) {
            mode |= GpgME::Signatures;
        }
        if (validate) {
            mode |= GpgME::Validate;
            /* Setting the context to offline mode disables CRL / OCSP checks in
               this Job. Otherwise we would try to fetch the CRL's for all CMS
               keys in the users keyring because GpgME::Validate includes remote
               resources by default in the validity check.
               This setting only has any effect if gpgsm >= 2.1.6 is used.
               */
            context->setOffline(true);
        }
        context->setKeyListMode(mode);
        return new QGpgME::QGpgMEListAllKeysJob(context);
    }

    QGpgME::EncryptJob *encryptJob(bool armor, bool textmode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setArmor(armor);
        context->setTextMode(textmode);
        return new QGpgME::QGpgMEEncryptJob(context);
    }

    QGpgME::DecryptJob *decryptJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEDecryptJob(context);
    }

    QGpgME::SignJob *signJob(bool armor, bool textMode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setArmor(armor);
        context->setTextMode(textMode);
        return new QGpgME::QGpgMESignJob(context);
    }

    QGpgME::VerifyDetachedJob *verifyDetachedJob(bool textMode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setTextMode(textMode);
        return new QGpgME::QGpgMEVerifyDetachedJob(context);
    }

    QGpgME::VerifyOpaqueJob *verifyOpaqueJob(bool textMode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setTextMode(textMode);
        return new QGpgME::QGpgMEVerifyOpaqueJob(context);
    }

    QGpgME::KeyGenerationJob *keyGenerationJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEKeyGenerationJob(context);
    }

    QGpgME::ImportJob *importJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEImportJob(context);
    }

    QGpgME::ImportFromKeyserverJob *importFromKeyserverJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEImportFromKeyserverJob(context);
    }

    QGpgME::ExportJob *publicKeyExportJob(bool armor) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setArmor(armor);
        return new QGpgME::QGpgMEExportJob(context);
    }

    QGpgME::ExportJob *secretKeyExportJob(bool armor, const QString &charset) const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::CMS) { // fixme: add support for gpg, too
            return nullptr;
        }

        // this operation is not supported by gpgme, so we have to call gpgsm ourselves:
        return new QGpgME::QGpgMESecretKeyExportJob(armor, charset);
    }

    QGpgME::RefreshKeysJob *refreshKeysJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::CMS) { // fixme: add support for gpg, too
            return nullptr;
        }

        // this operation is not supported by gpgme, so we have to call gpgsm ourselves:
        return new QGpgME::QGpgMERefreshKeysJob();
    }

    QGpgME::DownloadJob *downloadJob(bool armor) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setArmor(armor);
        // this is the hackish interface for downloading from keyserers currently:
        context->setKeyListMode(GpgME::Extern);
        return new QGpgME::QGpgMEDownloadJob(context);
    }

    QGpgME::DeleteJob *deleteJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEDeleteJob(context);
    }

    QGpgME::SignEncryptJob *signEncryptJob(bool armor, bool textMode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setArmor(armor);
        context->setTextMode(textMode);
        return new QGpgME::QGpgMESignEncryptJob(context);
    }

    QGpgME::DecryptVerifyJob *decryptVerifyJob(bool textMode) const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }

        context->setTextMode(textMode);
        return new QGpgME::QGpgMEDecryptVerifyJob(context);
    }

    QGpgME::ChangeExpiryJob *changeExpiryJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;    // only supported by gpg
        }

        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEChangeExpiryJob(context);
    }

    QGpgME::ChangePasswdJob *changePasswdJob() const Q_DECL_OVERRIDE
    {
        if (!GpgME::hasFeature(GpgME::PasswdFeature, 0)) {
            return nullptr;
        }
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEChangePasswdJob(context);
    }

    QGpgME::SignKeyJob *signKeyJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;    // only supported by gpg
        }

        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMESignKeyJob(context);
    }

    QGpgME::ChangeOwnerTrustJob *changeOwnerTrustJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;    // only supported by gpg
        }

        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEChangeOwnerTrustJob(context);
    }

    QGpgME::AddUserIDJob *addUserIDJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;    // only supported by gpg
        }

        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEAddUserIDJob(context);
    }

    QGpgME::KeyListJob *locateKeysJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;
        }
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        context->setKeyListMode(GpgME::Extern | GpgME::Local | GpgME::Signatures | GpgME::Validate);
        return new QGpgME::QGpgMEKeyListJob(context);
    }

    QGpgME::KeyForMailboxJob *keyForMailboxJob() const Q_DECL_OVERRIDE
    {
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEKeyForMailboxJob(context);
    }

    QGpgME::WKSPublishJob *wksPublishJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;
        }
        auto context = GpgME::Context::createForEngine(GpgME::SpawnEngine);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEWKSPublishJob(context.release());
    }

    QGpgME::TofuPolicyJob *tofuPolicyJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;
        }
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMETofuPolicyJob(context);
    }

    QGpgME::QuickJob *quickJob() const Q_DECL_OVERRIDE
    {
        if (mProtocol != GpgME::OpenPGP) {
            return nullptr;
        }
        GpgME::Context *context = GpgME::Context::createForProtocol(mProtocol);
        if (!context) {
            return nullptr;
        }
        return new QGpgME::QGpgMEQuickJob(context);
    }
};

}
#endif

/*
    protocol.h

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
#ifndef __QGPGME_PROTOCOL_H__
#define __QGPGME_PROTOCOL_H__

#include <QString>
#include <QVariant>

#include "qgpgme_export.h"

namespace QGpgME {
class AddExistingSubkeyJob;
class CryptoConfig;
class KeyListJob;
class ListAllKeysJob;
class KeyGenerationJob;
class ImportJob;
class ImportFromKeyserverJob;
class ExportJob;
class DownloadJob;
class DeleteJob;
class EncryptArchiveJob;
class EncryptJob;
class DecryptJob;
class SignArchiveJob;
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
class KeyForMailboxJob;
class WKDLookupJob;
class WKSPublishJob;
class TofuPolicyJob;
class QuickJob;
class GpgCardJob;
class ReceiveKeysJob;
class RevokeKeyJob;
class SetPrimaryUserIDJob;

/** The main entry point for QGpgME Comes in OpenPGP and SMIME(CMS) flavors.
 *
 * Use the proctocol class to obtain an instance of a job. Jobs
 * provide async API for GnuPG that can be connected to signals / slots.
 *
 * A job is usually started with start() and emits a result signal.
 * The parameters of the result signal depend on the job but the last
 * two are always a QString for the auditlog and an GpgME::Error for
 * an eventual error.
 *
 * In case async API is used and the result signal is emitted a
 * job schedules its own deletion.
 *
 * Most jobs also provide a synchronous call exec in which case
 * you have to explicitly delete the job if you don't need it anymore.
 *
 * \code
 * // Async example:
 * KeyListJob *job = openpgp()->keyListJob();
 * connect(job, &KeyListJob::result, job, [this, job](KeyListResult, std::vector<Key> keys, QString, Error)
 * {
 *    // keys and resuls can now be used.
 * });
 * job->start({QStringLiteral("alfa@example.net")}, false);
 * \endcode
 *
 * \code
 * // Sync eaxmple:
 * KeyListJob *job = openpgp()->keyListJob(false, false, false);
 * std::vector<GpgME::Key> keys;
 * GpgME::KeyListResult result = job->exec(QStringList() <<
 *                                         QStringLiteral("alfa@example.net"),
 *                                         false, keys);
 * delete job;
 * \endcode
 */
class QGPGME_EXPORT Protocol
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
    // the second parameter is ignored; the passphrase in the exported file is always utf-8 encoded
    virtual ExportJob            *secretKeyExportJob(bool armor = false, const QString & = QString()) const = 0;
    virtual DownloadJob          *downloadJob(bool armor = false) const = 0;
    virtual DeleteJob            *deleteJob() const = 0;
    virtual SignEncryptJob       *signEncryptJob(bool armor = false, bool textMode = false) const = 0;
    virtual DecryptVerifyJob     *decryptVerifyJob(bool textmode = false) const = 0;

    /**
     * For S/MIME keys this job performs a full validation check of the keys
     * with updated CRLs.
     * For OpenPGP keys, use receiveKeysJob.
     */
    virtual RefreshKeysJob       *refreshKeysJob() const = 0;
    virtual ChangeExpiryJob      *changeExpiryJob() const = 0;
    virtual SignKeyJob           *signKeyJob() const = 0;
    virtual ChangePasswdJob      *changePasswdJob() const = 0;
    virtual ChangeOwnerTrustJob  *changeOwnerTrustJob() const = 0;
    virtual AddUserIDJob         *addUserIDJob() const = 0;
    virtual SpecialJob           *specialJob(const char *type, const QMap<QString, QVariant> &args) const = 0;

    /** A key locate job.
     *
     * This tries to find a key in local
     * and remote sources, if the key was remote it is imported
     * by GnuPG. Same as KeyListJob but intended to be used
     * to locate keys automatically. This ends up calling --locate-keys.
     *
     * Only available for OpenPGP
     *
     * Results are validated. As if keyListJob was called
     * with both includeSigs and validate options.
     */
    virtual KeyListJob *locateKeysJob() const = 0;
    /** Find the best key to use for a mailbox. */
    virtual KeyForMailboxJob *keyForMailboxJob() const = 0;

    /** A Job for interacting with gnupg's wks tools. */
    virtual WKSPublishJob *wksPublishJob() const = 0;

    /** A Job to set tofu policy */
    virtual TofuPolicyJob *tofuPolicyJob() const = 0;

    /** A Job for the quick commands */
    virtual QuickJob *quickJob() const = 0;

    /** This job looks up a key via WKD without importing it. */
    virtual WKDLookupJob *wkdLookupJob() const = 0;

    virtual ExportJob *secretSubkeyExportJob(bool armor = false) const = 0;
    virtual AddExistingSubkeyJob *addExistingSubkeyJob() const = 0;
    virtual ReceiveKeysJob *receiveKeysJob() const = 0;

    virtual RevokeKeyJob *revokeKeyJob() const = 0;

    /**
     * Returns a job for flagging a user ID as the primary user ID of an
     * OpenPGP key.
     */
    virtual SetPrimaryUserIDJob *setPrimaryUserIDJob() const = 0;

    virtual EncryptArchiveJob *encryptArchiveJob(bool armor = false) const = 0;
    virtual SignArchiveJob *signArchiveJob(bool armor = false) const = 0;
};

/** Obtain a reference to the OpenPGP Protocol.
 *
 * The reference is to a static object.
 * @returns Reference to the OpenPGP Protocol.
 */
QGPGME_EXPORT Protocol *openpgp();

/** Obtain a reference to the smime Protocol.
 *
 * The reference is to a static object.
 * @returns Reference to the smime Protocol.
 */
QGPGME_EXPORT Protocol *smime();

/** Obtain a reference to a cryptoConfig object.
 *
 * The reference is to a static object.
 * @returns reference to cryptoConfig object.
 */
QGPGME_EXPORT CryptoConfig *cryptoConfig();

/** Obtain a reference to a protocol agnostic GpgCardJob.
 *
 * The reference is to a static object.
 * @returns reference to a GpgCardJob following the job pattern.
 */
QGPGME_EXPORT GpgCardJob *gpgCardJob();

}
#endif

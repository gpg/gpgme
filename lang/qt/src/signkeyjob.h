/*
    signkeyjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_SIGNKEYJOB_H__
#define __KLEO_SIGNKEYJOB_H__

#include "job.h"

#include <vector>

namespace GpgME
{
class Error;
class Key;
enum class TrustSignatureTrust : char;
}

class QDate;
class QString;

namespace QGpgME
{

/**
   @short An abstract base class to sign keys asynchronously

   To use a SignKeyJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the job with a call
   to start(). This call might fail, in which case the ChangeExpiryJob
   instance will have scheduled it's own destruction with a call to
   QObject::deleteLater().

   After result() is emitted, the SignKeyJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT SignKeyJob : public Job
{
    Q_OBJECT
protected:
    explicit SignKeyJob(QObject *parent);
public:
    ~SignKeyJob();

    /**
       Starts the key signing operation. \a key is the key to sign.
       @param keyToSign the key to be signed
     */
    virtual GpgME::Error start(const GpgME::Key &keyToSign) = 0;

    /**
     * If explicitly specified, only the listed user IDs will be signed. Otherwise all user IDs
     * are signed.
     * @param idsToSign list of user ID indexes (of the key to be signed).
     */
    virtual void setUserIDsToSign(const std::vector<unsigned int> &idsToSign) = 0;

    /**
     * sets the check level
     * @param checkLevel the check level, ranges from 0 (no claim) and 3 (extensively checked),
     * default is 0
     */
    virtual void setCheckLevel(unsigned int checkLevel) = 0;

    /**
     * sets whether the signature should be exportable, or local only.
     * default is local.
     */
    virtual void setExportable(bool exportable) = 0;

    /**
     * sets an alternate signing key
     */
    virtual void setSigningKey(const GpgME::Key &key) = 0;

    /**
     * if set, the created signature won't be revocable. By default signatures
     * can be revoked.
     */
    virtual void setNonRevocable(bool nonRevocable) = 0;

    /**
     * Set this if it is ok to overwrite an existing signature. In that
     * case the context has to have the flag "extended-edit" set to 1 through
     * Context::setFlag before calling edit.
     *
     * Not pure virtual for ABI compatibility.
     **/
    virtual void setDupeOk(bool) {}

    /**
     * Add a remark to the signature. This uses rem@gnupg.org as a notation.
     *
     * Not pure virtual for ABI compatibility.
     **/
    virtual void setRemark(const QString &) {}

    /**
     * If set, then the created signature will be a trust signature. By default,
     * no trust signatures are created.
     *
     * @a trust is the amount of trust to put into the signed key, either
     *          @c TrustSignatureTrust::Partial or @c TrustSignatureTrust::Complete.
     * @a depth is the level of the trust signature. Values between 0 and 255 are
     *          allowed. Level 0 has the same meaning as an ordinary validity signature.
     *          Level 1 means that the signed key is asserted to be a valid trusted
     *          introducer. Level n >= 2 means that the signed key is asserted to be
     *          trusted to issue level n-1 trust signatures, i.e., that it is a "meta
     *          introducer".
     * @a scope is a domain name that limits the scope of trust of the signed key
     *          to user IDs with email addresses matching the domain (or a subdomain).
     *
     * Not pure virtual for ABI compatibility.
     **/
    virtual void setTrustSignature(GpgME::TrustSignatureTrust trust, unsigned short depth, const QString &scope) { Q_UNUSED(trust); Q_UNUSED(depth); Q_UNUSED(scope); }

    /**
     * Sets the expiration date of the key signature to @a expiration. By default,
     * key signatures do not expire.
     *
     * Note: Expiration dates after 2106-02-06 will be set to 2106-02-06.
     *
     * Not pure virtual for ABI compatibility.
     **/
    virtual void setExpirationDate(const QDate &expiration) { Q_UNUSED(expiration); }

Q_SIGNALS:
    void result(const GpgME::Error &result, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_SIGNKEYJOB_H__

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
}

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
       @param idsToSign the user IDs to sign
       @param signingKey the secret key to use for signing
       @param option the signing mode, either local or exportable
     */
    virtual GpgME::Error start(const GpgME::Key &keyToSign) = 0;

    /**
     * If explicitly specified, only the listed user IDs will be signed. Otherwise all user IDs
     * are signed.
     * @param list of user ID indexes (of the key to be signed).
     */
    virtual void setUserIDsToSign(const std::vector<unsigned int> &idsToSign) = 0;

    /**
     * sets the check level
     * @param the check level, ranges from 0 (no claim) and 3 (extensively checked),
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

Q_SIGNALS:
    void result(const GpgME::Error &result, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_SIGNKEYJOB_H__

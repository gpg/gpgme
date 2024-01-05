/*
    verifydetachedjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004, 2007 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_VERIFYDETACHEDJOB_H__
#define __KLEO_VERIFYDETACHEDJOB_H__

#include "job.h"

#include <memory>

class QByteArray;
class QIODevice;

namespace GpgME
{
class Error;
class VerificationResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous verification of detached signatures

   To use a VerifyDetachedJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the verification with a
   call to start(). This call might fail, in which case the
   VerifyDetachedJob instance will have scheduled it's own
   destruction with a call to QObject::deleteLater().

   Alternatively, the job can be started with startIt() after setting
   the input files. If the job is started this way then the backend reads the
   input directly from the specified input files. This direct IO mode is
   currently only supported for OpenPGP. Note that startIt() does not schedule
   the job's destruction if starting the job failed.

   After result() is emitted, the VerifyDetachedJob will schedule
   it's own destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT VerifyDetachedJob : public Job
{
    Q_OBJECT
protected:
    explicit VerifyDetachedJob(QObject *parent);
public:
    ~VerifyDetachedJob() override;

    /**
     * Sets the path of the file containing the signature to verify.
     *
     * Used if the job is started with startIt().
     */
    void setSignatureFile(const QString &path);
    QString signatureFile() const;

    /**
     * Sets the path of the file containing the signed data to verify.
     *
     * Used if the job is started with startIt().
     */
    void setSignedFile(const QString &path);
    QString signedFile() const;

    /**
       Starts the verification operation. \a signature contains the
       signature data, while \a signedData contains the data over
       which the signature was made.
    */
    virtual GpgME::Error start(const QByteArray &signature,
            const QByteArray &signedData) = 0;

    virtual void start(const std::shared_ptr<QIODevice> &signature, const std::shared_ptr<QIODevice> &signedData) = 0;

    virtual GpgME::VerificationResult exec(const QByteArray &signature,
                                           const QByteArray &signedData) = 0;

Q_SIGNALS:
    void result(const GpgME::VerificationResult &result, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_VERIFYDETACHEDJOB_H__

/*
    decryptverifyjob.h

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

#ifndef __KLEO_DECRYPTVERIFYJOB_H__
#define __KLEO_DECRYPTVERIFYJOB_H__

#include "job.h"

#include <memory>

class QByteArray;
class QIODevice;

namespace GpgME
{
class Error;
class DecryptionResult;
class VerificationResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous combined decrypters and verifiers

   To use a DecryptVerifyJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the operation with a
   call to start(). This call might fail, in which case the
   DecryptVerifyJob instance will have scheduled it's own destruction with
   a call to QObject::deleteLater().

   Alternatively, the job can be started with startIt() after setting
   an input file and an output file. If the job is started this way then
   the backend reads the input and writes the output directly from/to the
   specified input file and output file. In this case the plainText value of
   the result signal will always be empty. This direct IO mode is currently
   only supported for OpenPGP. Note that startIt() does not schedule the job's
   destruction if starting the job failed.

   After result() is emitted, the DecryptVerifyJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT DecryptVerifyJob : public Job
{
    Q_OBJECT
protected:
    explicit DecryptVerifyJob(QObject *parent);
public:
    ~DecryptVerifyJob() override;

    /**
     * Sets the path of the file to decrypt (and verify).
     *
     * Used if the job is started with startIt().
     */
    void setInputFile(const QString &path);
    QString inputFile() const;

    /**
     * Sets the path of the file to write the result to.
     *
     * Used if the job is started with startIt().
     *
     * \note If a file with this path exists, then the job will fail, i.e. you
     * need to delete an existing file that shall be overwritten before you
     * start the job.
     */
    void setOutputFile(const QString &path);
    QString outputFile() const;

    /**
       Starts the combined decryption and verification operation.
       \a cipherText is the data to decrypt and later verify.
    */
    virtual GpgME::Error start(const QByteArray &cipherText) = 0;

    /*!
      \overload

      If \a plainText is non-null, the plaintext is written
      there. Otherwise, it will be delivered in the third argument
      of result().
    */
    virtual void start(const std::shared_ptr<QIODevice> &cipherText, const std::shared_ptr<QIODevice> &plainText = std::shared_ptr<QIODevice>()) = 0;

    /** Synchronous equivalent of start() */
    virtual std::pair<GpgME::DecryptionResult, GpgME::VerificationResult>
    exec(const QByteArray &cipherText, QByteArray &plainText) = 0;

Q_SIGNALS:
    void result(const GpgME::DecryptionResult &decryptionresult,
                const GpgME::VerificationResult &verificationresult,
                const QByteArray &plainText, const QString &auditLogAsHtml = QString(),
                const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_DECRYPTVERIFYJOB_H__

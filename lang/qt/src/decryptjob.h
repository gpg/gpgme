/*
    decryptjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004, 2007 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

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

#ifndef __KLEO_DECRYPTJOB_H__
#define __KLEO_DECRYPTJOB_H__

#include "job.h"

#include <memory>

class QByteArray;
class QIODevice;

namespace GpgME
{
class Error;
class DecryptionResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous decrypters

   To use a DecryptJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the decryption with a
   call to start(). This call might fail, in which case the
   DecryptJob instance will have scheduled it's own destruction with
   a call to QObject::deleteLater().

   After result() is emitted, the DecryptJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT DecryptJob : public Job
{
    Q_OBJECT
protected:
    explicit DecryptJob(QObject *parent);
public:
    ~DecryptJob();

    /**
       Starts the decryption operation. \a cipherText is the data to
       decrypt.
    */
    virtual QGPGME_DEPRECATED_EXPORT GpgME::Error start(const QByteArray &cipherText) = 0;

    /*!
      \overload

      If \a plainText is non-null, the plaintext is written
      there. Otherwise, it will be delivered in the second argument
      of result().

      \throws GpgME::Exception if starting fails
    */
    virtual void start(const std::shared_ptr<QIODevice> &cipherText, const std::shared_ptr<QIODevice> &plainText = std::shared_ptr<QIODevice>()) = 0;

    virtual GpgME::DecryptionResult exec(const QByteArray &cipherText,
                                         QByteArray &plainText) = 0;

Q_SIGNALS:
    void result(const GpgME::DecryptionResult &result, const QByteArray &plainText, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_DECRYPTJOB_H__

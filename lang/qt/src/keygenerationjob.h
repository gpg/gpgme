/*
    keygenerationjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_KEYGENERATIONJOB_H__
#define __KLEO_KEYGENERATIONJOB_H__

#include "job.h"

#include <QtCore/QByteArray>

namespace GpgME
{
class Error;
class KeyGenerationResult;
}

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous key generation

   To use a KeyGenerationJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the key generation with
   a call to start(). This call might fail, in which case the
   KeyGenerationJob instance will have scheduled it's own
   destruction with a call to QObject::deleteLater().

   After result() is emitted, the KeyGenerationJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class KeyGenerationJob : public Job
{
    Q_OBJECT
protected:
    explicit KeyGenerationJob(QObject *parent);
public:
    ~KeyGenerationJob();

    /**
       Starts the key generation operation. \a parameters is a
       backend-specific string containing the parameters of the key to
       create (length, capabilities, etc).
    */
    virtual GpgME::Error start(const QString &parameters) = 0;

Q_SIGNALS:
    void result(const GpgME::KeyGenerationResult &result, const QByteArray &pubKeyData, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}

#endif // __KLEO_KEYGENERATIONJOB_H__

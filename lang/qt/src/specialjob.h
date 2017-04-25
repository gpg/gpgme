/*
    specialjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_SPECIALJOB_H__
#define __KLEO_SPECIALJOB_H__

#include "job.h"
#include "qgpgme_export.h"

namespace GpgME
{
class Error;
}

namespace QGpgME
{

/**
   @short An abstract base class for protocol-specific jobs

   To use a SpecialJob, first obtain an instance from the
   CryptoBackend implementation, connect progress() and result()
   signals to suitable slots and then start the job with a call to
   start(). This call might fail, in which case the SpecialJob
   instance will have schedules its own destruction with a call to
   QObject::deleteLater().

   After result() is emitted, the SpecialJob will schedule its own
   destruction by calling QObject::deleteLater().

   Parameters are set using the Qt property system. More general, or
   constructor parameters are given in the call to
   QGpgME::Protocol::specialJob().

   The result is made available through the result signal, and
   through the read-only result property, the latter of which needs
   to be defined in each SpecialJob subclass.
*/
class QGPGME_EXPORT SpecialJob : public Job
{
    Q_OBJECT
protected:
    explicit SpecialJob(QObject *parent);

public:
    ~SpecialJob();

    /**
       Starts the special operation.
    */
    virtual GpgME::Error start() = 0;

    virtual GpgME::Error exec() = 0;

Q_SIGNALS:
    void result(const GpgME::Error &result, const QVariant &data);
};

}

#endif // __KLEO_SPECIALJOB_H__

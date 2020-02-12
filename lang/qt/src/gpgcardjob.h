/*
    gpgcardjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2020 g10 Code GmbH

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
#ifndef __KLEO_GPGCARDJOB_H__
#define __KLEO_GPGCARDJOB_H__

#include <QStringList>

#include "job.h"

namespace GpgME
{
class Error;
}

namespace QGpgME
{

/**
   @short Get the best key to use for a Mailbox

   To use the keyformailboxjob, first obtain an instance from the
   CryptoBackend and either exec it or start and
   conncet the result() signals to a suitable slot.
   The job will be automatically deleted in which
   case the KeylistJob instance will have schedules it's own
   destruction with a call to QObject::deleteLater().

   The best key is defined as the key with a UID that has an
   E-Mail that matches the mailbox provided. If multiple
   keys are found the one with the highest validity is returned.

   After result() is emitted, the
   KeyListJob will schedule it's own destruction by calling
   QObject::deleteLater().
*/
class QGPGME_EXPORT GpgCardJob: public Job
{
    Q_OBJECT
protected:
    explicit GpgCardJob(QObject *parent);

public:
    ~GpgCardJob();

    /**
      Starts the operation. \a cmds are the commands to
      execute.
    */
    virtual GpgME::Error start(const QStringList &cmds) = 0;

    virtual GpgME::Error exec(const QStringList &cmds, QString &std_out, QString &std_err, int &exitCode) = 0;

Q_SIGNALS:
    /** The resulting stdout and stderr of gpgcard and the exitCode
     *
     * The auditlog params are always null / empty.
     */
    void result(const QString &std_out, const QString &std_err, int exitCode,
                const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}
#endif

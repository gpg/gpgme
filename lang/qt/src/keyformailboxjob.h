/*
    keyformailboxjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
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
#ifndef __KLEO_KEYFORMAILBOX_H__
#define __KLEO_KEYFORMAILBOX_H__

#include <QString>

#include "job.h"

#include <gpgme++/key.h>

namespace GpgME
{
class Error;
class KeyListResult;
}

namespace QGpgME
{

/**
   @short Get the best key to use for a Mailbox

   To use the keyformailboxjob, first obtain an instance from the
   CryptoBackend and either exec it or start and
   connect the result() signal to a suitable slot.

   The best key is defined as the key with a UID that has an
   E-Mail that matches the mailbox provided. If multiple
   keys are found the one with the highest validity is returned.

   After result() is emitted, the job will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT KeyForMailboxJob: public Job
{
    Q_OBJECT
protected:
    explicit KeyForMailboxJob(QObject *parent);

public:
    ~KeyForMailboxJob();

    /**
      Starts the operation. \a mailbox is the mailbox to
      look for.

      The result is the same as for the LocateKeysJob.

      If \a canEncrypt is true, only keys that have a subkey for encryption
      usage are returned. Use this if you need to select a
      key for signing.
    */
    virtual GpgME::Error start(const QString &mailbox, bool canEncrypt = true) = 0;

    virtual GpgME::KeyListResult exec(const QString &mailbox, bool canEncrypt, GpgME::Key &key, GpgME::UserID &uid) = 0;

Q_SIGNALS:
    /** The result. \a Key is the key found or a Null key.
     *
     * The userid is the uid where the mailbox matches.
     *
     * The auditlog params are always null / empty.
     */
    void result(const GpgME::KeyListResult &result, const GpgME::Key &key, const GpgME::UserID &uid, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}
#endif

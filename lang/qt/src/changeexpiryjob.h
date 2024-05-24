/*
    changeexpiryjob.h

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

#ifndef __KLEO_CHANGEEXPIRYJOB_H__
#define __KLEO_CHANGEEXPIRYJOB_H__

#include "job.h"

#include <gpgme++/key.h>

#include <vector>

namespace GpgME
{
class Error;
}

class QDateTime;

namespace QGpgME
{

/**
   @short An abstract base class to change expiry asynchronously

   To use a ChangeExpiryJob, first obtain an instance from the
   CryptoBackend implementation, connect the progress() and result()
   signals to suitable slots and then start the job with a call
   to start(). This call might fail, in which case the ChangeExpiryJob
   instance will have scheduled it's own destruction with a call to
   QObject::deleteLater().

   After result() is emitted, the ChangeExpiryJob will schedule it's own
   destruction by calling QObject::deleteLater().
*/
class QGPGME_EXPORT ChangeExpiryJob : public Job
{
    Q_OBJECT
public:
    enum Option {
        Default = 0x00,
        UpdatePrimaryKey = 0x01,
        UpdateAllSubkeys = 0x02,
    };
    Q_DECLARE_FLAGS(Options, Option)

protected:
    explicit ChangeExpiryJob(QObject *parent);
public:
    ~ChangeExpiryJob();

    void setOptions(Options options);
    Options options() const;

    /**
       Starts the change-expiry operation. \a key is the key to change
       the expiry of. \a expiry is the new expiry time. If \a expiry
       is not valid, \a key is set to never expire.
    */
    virtual GpgME::Error start(const GpgME::Key &key, const QDateTime &expiry) = 0;

    /**
       Starts the change-expiry operation. \a key is the key to change,
       \a subkeys is a list of subkeys of the key, and \a expiry is the
       new expiry time. If \a subkeys is empty, then the expiry of \a key
       is changed. Otherwise, the expiry of \a subkeys is changed. If
       \a expiry is not valid, then \a key or \a subkeys are set to never expire.
    */
    virtual GpgME::Error start(const GpgME::Key &key, const QDateTime &expiry,
                               const std::vector<GpgME::Subkey> &subkeys);

Q_SIGNALS:
    void result(const GpgME::Error &result, const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

Q_DECLARE_OPERATORS_FOR_FLAGS(ChangeExpiryJob::Options)

}

#endif // __KLEO_CHANGEEXPIRYJOB_H__

/*  quickjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2017 Intevation GmbH
    Copyright (c) 2020 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    QGpgME is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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
#ifndef QGPGME_QUICKJOB_H
#define QGPGME_QUICKJOB_H

#include "job.h"

#include "qgpgme_export.h"

#include <QDateTime>

#include <gpgme++/key.h>

class QString;

namespace QGpgME{

/**
 * Interface to the modern key manipulation functions.
 */
class QGPGME_EXPORT QuickJob : public Job
{
    Q_OBJECT
public:
    explicit QuickJob(QObject *parent = nullptr);
    ~QuickJob();

    /** Start --quick-gen-key */
    virtual void startCreate(const QString &uid,
                             const char *algo,
                             const QDateTime &expires = QDateTime(),
                             const GpgME::Key &key = GpgME::Key(),
                             unsigned int flags = 0) = 0;

    /** Start --quick-adduid */
    virtual void startAddUid(const GpgME::Key &key, const QString &uid) = 0;

    /** Start --quick-revuid */
    virtual void startRevUid(const GpgME::Key &key, const QString &uid) = 0;

    /** Start --quick-add-key */
    virtual void startAddSubkey(const GpgME::Key &key, const char *algo,
                                const QDateTime &expires = QDateTime(),
                                unsigned int flags = 0) = 0;

    /**
       Starts the operation to revoke the signatures made with the key \a signingKey on the
       user IDs \a userIds of the key \a key. If \a userIds is an empty list, then all
       signatures made with \a signingKey on the user IDs of \a key will be revoked.
    */
    virtual void startRevokeSignature(const GpgME::Key &key, const GpgME::Key &signingKey,
                                      const std::vector<GpgME::UserID> &userIds = std::vector<GpgME::UserID>()) = 0;

    /** Start --quick-add-adsk */
    virtual void startAddAdsk(const GpgME::Key &key, const char *adsk) = 0;

    /**
     * Starts the operation to enable or disable the OpenPGP key \a key.
     * If \a enabled is \c true then the key is enabled. Otherwise, the key is disabled.
     *
     * \note Requires gpg 2.4.6.
     */
    GpgME::Error startSetKeyEnabled(const GpgME::Key &key, bool enabled);

Q_SIGNALS:
    void result(const GpgME::Error &error,
                const QString &auditLogAsHtml = QString(), const GpgME::Error &auditLogError = GpgME::Error());
};

}
#endif

/*  qgpgmequickjob.h

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
#ifndef QGPGME_QGPGMEQUICKJOB_H
#define QGPGME_QGPGMEQUICKJOB_H

#include "quickjob.h"

#include "threadedjobmixin.h"

namespace QGpgME
{

/**
 * Interface to the modern key manipulation functions.
 */
class QGpgMEQuickJob
#ifdef Q_MOC_RUN
    : public QuickJob
#else
    : public _detail::ThreadedJobMixin<QuickJob>
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEQuickJob(GpgME::Context *context);
    ~QGpgMEQuickJob();

    void startCreate(const QString &uid,
                     const char *algo,
                     const QDateTime &expires = QDateTime(),
                     const GpgME::Key &key = GpgME::Key(),
                     unsigned int flags = 0) override;
    void startAddUid(const GpgME::Key &key, const QString &uid) override;
    void startRevUid(const GpgME::Key &key, const QString &uid) override;
    void startAddSubkey(const GpgME::Key &key, const char *algo,
                        const QDateTime &expires = QDateTime(),
                        unsigned int flags = 0) override;
    void startRevokeSignature(const GpgME::Key &key, const GpgME::Key &signingKey,
                              const std::vector<GpgME::UserID> &userIds = std::vector<GpgME::UserID>()) override;
    void startAddAdsk(const GpgME::Key &key, const char *adsk) override;
};

}
#endif

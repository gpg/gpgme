/* qgpgmewkspublishjob.h

    Copyright (c) 2016 Intevation GmbH

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
#ifndef QGPGME_QGPGMEWKSPUBLISHJOB_H
#define QGPGME_QGPGMEWKSPUBLISHJOB_H

#include "wkspublishjob.h"

#include "threadedjobmixin.h"
namespace GpgME
{
    class Key;
} // namespace GpgME

namespace QGpgME {

/**
 * Handles Web Key Service Publishing. Needs WKS tools installed and
 * server support.
 */
class QGpgMEWKSPublishJob
#ifdef Q_MOC_RUN
    : public WKSPublishJob
#else
    : public _detail::ThreadedJobMixin<WKSPublishJob, std::tuple<GpgME::Error, QByteArray, QByteArray, QString, GpgME::Error> >
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEWKSPublishJob(GpgME::Context *context);
    ~QGpgMEWKSPublishJob();

    void startCheck(const QString &mailbox) Q_DECL_OVERRIDE;
    void startCreate(const char *fpr, const QString &mailbox) Q_DECL_OVERRIDE;
    void startReceive(const QByteArray &response) Q_DECL_OVERRIDE;
};

}

#endif

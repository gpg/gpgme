/*
    qgpgmeadduseridjob.h

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

#ifndef __QGPGME_QGPGMEADDUSERIDJOB_H__
#define __QGPGME_QGPGMEADDUSERIDJOB_H__

#include "adduseridjob.h"

#include "threadedjobmixin.h"

namespace QGpgME
{

class QGpgMEAddUserIDJob
#ifdef Q_MOC_RUN
    : public AddUserIDJob
#else
    : public _detail::ThreadedJobMixin<AddUserIDJob>
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
private Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEAddUserIDJob(GpgME::Context *context);
    ~QGpgMEAddUserIDJob();

    /* from AddUserIDJob */
    GpgME::Error start(const GpgME::Key &key, const QString &name, const QString &email, const QString &comment) override;
};
}

#endif // __QGPGME_QGPGMEADDUSERIDJOB_H__

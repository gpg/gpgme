/*  qgpgmegpgcardjob.h

    This file is part of libkleopatra, the KDE keymanagement library
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

#ifndef __QGPGME_QGPGMEGPGCARDJOB_H__
#define __QGPGME_QGPGMEGPGCARDJOB_H__
#include "gpgcardjob.h"

#include "threadedjobmixin.h"

namespace QGpgME
{

class QGpgMEGpgCardJob
#ifdef Q_MOC_RUN
    : public GpgCardJob
#else
    : public _detail::ThreadedJobMixin<GpgCardJob, std::tuple<QString, QString, int, QString, GpgME::Error> >
#endif
{
    Q_OBJECT
#ifdef Q_MOC_RUN
public Q_SLOTS:
    void slotFinished();
#endif
public:
    explicit QGpgMEGpgCardJob();
    ~QGpgMEGpgCardJob();

    GpgME::Error start(const QStringList &cmds) override;

    GpgME::Error exec(const QStringList &cmds, QString &std_out, QString &std_err, int &exitCode) override;
};

}
#endif

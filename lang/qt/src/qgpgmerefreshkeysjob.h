/*
    qgpgmerefreshkeysjob.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

    Libkleopatra is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation; either version 2 of the
    License, or (at your option) any later version.

    Libkleopatra is distributed in the hope that it will be useful,
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

#ifndef __QGPGME_QGPGMEREFRESHKEYSJOB_H__
#define __QGPGME_QGPGMEREFRESHKEYSJOB_H__

#include "refreshkeysjob.h"
#ifdef BUILDING_QGPGME
# include "context.h"
#else
#include "gpgme++/context.h"
#endif

#include <QStringList>
#include <QProcess>

namespace QGpgME
{

class QGpgMERefreshKeysJob : public RefreshKeysJob
{
    Q_OBJECT
public:
    QGpgMERefreshKeysJob();
    ~QGpgMERefreshKeysJob();

    /*! \reimp from RefreshKeysJob */
    GpgME::Error start(const QStringList &patterns) Q_DECL_OVERRIDE;

private Q_SLOTS:
    /*! \reimp from Job */
    void slotCancel() Q_DECL_OVERRIDE;

    void slotStatus(QProcess *, const QString &, const QStringList &);
    void slotStderr();
    void slotProcessExited(int exitCode, QProcess::ExitStatus exitStatus);

private:
    GpgME::Error startAProcess();

private:
    QProcess *mProcess;
    GpgME::Error mError;
    QStringList mPatternsToDo;
};

}

#endif // __QGPGME_QGPGMEREFRESHKEYSJOB_H__

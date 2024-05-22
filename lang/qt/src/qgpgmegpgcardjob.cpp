/*
    qgpgmegpgcardjob.cpp

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

#include "qgpgmegpgcardjob.h"

#include <QStringList>
#include <QFileInfo>
#include <QDir>
#include <QProcess>
#include "util.h"
#include "qgpgme_debug.h"

/* We cannot have a timeout because key generation can
 * take ages. Well maybe 10 minutes. */
#define TIMEOUT_VALUE (600000)

#include <tuple>

using namespace GpgME;
using namespace QGpgME;

QGpgMEGpgCardJob::QGpgMEGpgCardJob()
    : mixin_type(/* needed for the mixer */
                 Context::createForEngine(GpgME::SpawnEngine).release())
{
    lateInitialization();
}

QGpgMEGpgCardJob::~QGpgMEGpgCardJob() {}

static QString getGpgCardPath()
{
    auto bindir = QString::fromLocal8Bit(dirInfo("bindir"));
    if (bindir.isEmpty()) {
        return QString();
    }

    const QFileInfo fi(QDir(bindir).absoluteFilePath(QStringLiteral("gpg-card")));
    if (fi.exists() && fi.isExecutable()) {
        return fi.absoluteFilePath();
    }
    return QString();
}

static QGpgMEGpgCardJob::result_type do_work(const QStringList &cmds, const QString &path)
{
    QStringList args;
    args << QStringLiteral("--with-colons");
    args += cmds;

    QProcess proc;

    proc.setProgram(path);
    proc.setArguments(args);

    qCDebug(QGPGME_LOG) << "Executing:" << path << args;
    proc.start();
    if (!proc.waitForStarted()) {
        return std::make_tuple (QString(), QString(), 1, QString(), Error());
    }

    if (!proc.waitForFinished(TIMEOUT_VALUE)) {
        return std::make_tuple (QString(), QString(), 1, QString(), Error());
    }
    if (proc.exitStatus() == QProcess::NormalExit) {
        return std::make_tuple (QString::fromUtf8(proc.readAllStandardOutput()),
                                QString::fromUtf8(proc.readAllStandardError()), proc.exitCode(),
                                QString(), Error());
    }
    return std::make_tuple (QString::fromUtf8(proc.readAllStandardOutput()),
            QString::fromUtf8(proc.readAllStandardError()), 1,
            QString(), Error());
}

Error QGpgMEGpgCardJob::start(const QStringList &cmds)
{
    const auto cardpath = getGpgCardPath ();
    if (cardpath.isEmpty()) {
        return Error(make_error(GPG_ERR_NOT_SUPPORTED));
    }
    run(std::bind(&do_work, cmds, cardpath));
    return Error();
}

Error QGpgMEGpgCardJob::exec(const QStringList &cmds, QString &std_out, QString &std_err, int &exitCode)
{
    const auto cardpath = getGpgCardPath ();
    if (cardpath.isEmpty()) {
        return Error(make_error(GPG_ERR_NOT_SUPPORTED));
    }
    const result_type r = do_work(cmds, cardpath);
    std_out = std::get<0>(r);
    std_err = std::get<1>(r);
    exitCode = std::get<2>(r);
    return exitCode == 0 ? Error() : Error(make_error(GPG_ERR_GENERAL));
}

#include "qgpgmegpgcardjob.moc"

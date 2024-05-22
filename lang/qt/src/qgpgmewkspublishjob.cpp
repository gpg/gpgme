/* wkspublishjob.cpp

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

#include "qgpgmewkspublishjob.h"

#include <gpgme++/context.h>
#include <gpgme++/key.h>

#include "util.h"

#include <QFileInfo>
#include <QDir>
#include <QProcess>

/* Timeout for the WKS Processes will be 5 Minutes as
 * they can involve pinentry questions. */
#define TIMEOUT_VALUE (5*60*1000)

using namespace QGpgME;
using namespace GpgME;

QGpgMEWKSPublishJob::QGpgMEWKSPublishJob(Context *context)
    : mixin_type(context)
{
    lateInitialization();
}

QGpgMEWKSPublishJob::~QGpgMEWKSPublishJob() {}

static QString getWKSClient()
{
    auto libexecdir = QString::fromLocal8Bit(dirInfo("libexecdir"));
    if (libexecdir.isEmpty()) {
        return QString();
    }

    const QFileInfo fi(QDir(libexecdir).absoluteFilePath(QStringLiteral("gpg-wks-client")));
    if (fi.exists() && fi.isExecutable()) {
        return fi.absoluteFilePath();
    }
    return QString();
}

static QGpgMEWKSPublishJob::result_type check_worker(const QString &mail)
{
    if (mail.isEmpty()) {
        return std::make_tuple (Error(make_error(GPG_ERR_INV_ARG)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    const auto wksPath = getWKSClient();
    if (wksPath.isEmpty()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    /* QProcess instead of engine_spawn because engine_spawn does not communicate
     * the return value of the process and we are in qt anyway. */
    QProcess proc;
    proc.setProgram(wksPath);
    proc.setArguments(QStringList() << QStringLiteral("--supported") << mail);
    proc.start();
    if (!proc.waitForStarted()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }
    if (!proc.waitForFinished(TIMEOUT_VALUE)) {
        return std::make_tuple (Error(make_error(GPG_ERR_TIMEOUT)),
                                QByteArray(), QByteArray(), QString(), Error());
    }
    if (proc.exitStatus() == QProcess::NormalExit && proc.exitCode() == 0) {
        return std::make_tuple (Error(), QByteArray(), QByteArray(), QString(), Error());
    }
    return std::make_tuple (Error(make_error(GPG_ERR_NOT_ENABLED)),
                            QByteArray(), QByteArray(), QString(), Error());
}

static QGpgMEWKSPublishJob::result_type create_worker(const char *fpr, const QString &mail)
{
    if (mail.isEmpty() || !fpr) {
        return std::make_tuple (Error(make_error(GPG_ERR_INV_ARG)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    const auto wksPath = getWKSClient();
    if (wksPath.isEmpty()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    QProcess proc;
    proc.setProgram(wksPath);
    proc.setArguments(QStringList() << QStringLiteral("--create")
                                    << QLatin1String(fpr)
                                    << mail);
    proc.start();
    if (!proc.waitForStarted()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    if (!proc.waitForFinished(TIMEOUT_VALUE)) {
        return std::make_tuple (Error(make_error(GPG_ERR_TIMEOUT)),
                                QByteArray(), QByteArray(), QString(), Error());
    }
    if (proc.exitStatus() == QProcess::NormalExit && proc.exitCode() == 0) {
        return std::make_tuple (Error(), proc.readAllStandardOutput(),
                                proc.readAllStandardError(), QString(), Error());
    }
    return std::make_tuple (Error(make_error(GPG_ERR_GENERAL)),
                            proc.readAllStandardOutput(), proc.readAllStandardError(), QString(), Error());
}

static QGpgMEWKSPublishJob::result_type receive_worker(const QByteArray &response)
{
    if (response.isEmpty()) {
        return std::make_tuple (Error(make_error(GPG_ERR_INV_ARG)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    const auto wksPath = getWKSClient();
    if (wksPath.isEmpty()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }

    QProcess proc;
    proc.setProgram(wksPath);
    proc.setArguments(QStringList() << QStringLiteral("--receive"));
    proc.start();
    if (!proc.waitForStarted()) {
        return std::make_tuple (Error(make_error(GPG_ERR_NOT_SUPPORTED)),
                                QByteArray(), QByteArray(), QString(), Error());
    }
    proc.write(response);
    proc.closeWriteChannel();
    if (!proc.waitForFinished(TIMEOUT_VALUE)) {
        return std::make_tuple (Error(make_error(GPG_ERR_TIMEOUT)),
                                QByteArray(), QByteArray(), QString(), Error());
    }
    if (proc.exitStatus() == QProcess::NormalExit && proc.exitCode() == 0) {
        return std::make_tuple (Error(), proc.readAllStandardOutput(),
                                proc.readAllStandardError(), QString(), Error());
    }
    return std::make_tuple (Error(make_error(GPG_ERR_GENERAL)),
                            proc.readAllStandardOutput(), proc.readAllStandardError(), QString(), Error());
}

void QGpgMEWKSPublishJob::startCheck(const QString &mailbox)
{
    run(std::bind(&check_worker, mailbox));
}

void QGpgMEWKSPublishJob::startCreate(const char *fpr, const QString &mailbox) {
    run(std::bind(&create_worker, fpr, mailbox));
}

void QGpgMEWKSPublishJob::startReceive(const QByteArray &response)
{
    run(std::bind(&receive_worker, response));
}

#include "qgpgmewkspublishjob.moc"

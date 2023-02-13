/*
    qgpgmerefreshsmimekeysjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarävdalens Datakonsult AB
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

#define MAX_CMD_LENGTH 32768

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "qgpgmerefreshsmimekeysjob.h"
#include "util.h"

#include <QDebug>
#include "qgpgme_debug.h"

#include "context.h"
#include <key.h>

#include <QByteArray>
#include <QMetaObject>
#include <QProcess>
#include <QStringList>

#include <gpg-error.h>

#include <assert.h>

using namespace QGpgME;

QGpgMERefreshSMIMEKeysJob::QGpgMERefreshSMIMEKeysJob()
    : RefreshKeysJob(nullptr),
      mProcess(nullptr),
      mError(0)
{

}

QGpgMERefreshSMIMEKeysJob::~QGpgMERefreshSMIMEKeysJob()
{

}

GpgME::Error QGpgMERefreshSMIMEKeysJob::start(const QStringList &patterns)
{
    assert(mPatternsToDo.empty());

    mPatternsToDo = patterns;
    if (mPatternsToDo.empty()) {
        mPatternsToDo.push_back(QStringLiteral(" "));    // empty list means all -> mae
    }
    // sure to fail the first
    // startAProcess() guard clause

    return startAProcess();
}

GpgME::Error QGpgMERefreshSMIMEKeysJob::start(const std::vector<GpgME::Key> &keys)
{
    if (keys.empty()) {
        QMetaObject::invokeMethod(this, [this]() {
            Q_EMIT slotProcessExited(0, QProcess::NormalExit);
        }, Qt::QueuedConnection);
        return {};
    }

    const bool gotWrongKeys = std::any_of(std::begin(keys), std::end(keys), [](const GpgME::Key &k) {
        return k.protocol() != GpgME::CMS;
    });
    if (gotWrongKeys) {
        qCDebug(QGPGME_LOG) << "Error: At least one of the keys is not an S/MIME key";
        return GpgME::Error::fromCode(GPG_ERR_INV_VALUE);
    }

    return start(toFingerprints(keys));
}

#if MAX_CMD_LENGTH < 65 + 128
#error MAX_CMD_LENGTH is too low
#endif

GpgME::Error QGpgMERefreshSMIMEKeysJob::startAProcess()
{
    if (mPatternsToDo.empty()) {
        return GpgME::Error();
    }
    // create and start gpgsm process:
    mProcess = new QProcess(this);
    mProcess->setObjectName(QStringLiteral("gpgsm -k --with-validation --force-crl-refresh --enable-crl-checks"));

    // FIXME: obbtain the path to gpgsm from gpgme, so we use the same instance.
    mProcess->setProgram(QStringLiteral("gpgsm"));
    QStringList arguments;
    arguments << QStringLiteral("-k")
              << QStringLiteral("--with-validation")
              << QStringLiteral("--force-crl-refresh")
              << QStringLiteral("--enable-crl-checks");
    unsigned int commandLineLength = MAX_CMD_LENGTH;
    commandLineLength -=
        strlen("gpgsm") + 1 + strlen("-k") + 1 +
        strlen("--with-validation") + 1 + strlen("--force-crl-refresh") + 1 +
        strlen("--enable-crl-checks") + 1;
    while (!mPatternsToDo.empty()) {
        const QByteArray pat = mPatternsToDo.front().toUtf8().trimmed();
        const unsigned int patLength = pat.length();
        if (patLength >= commandLineLength) {
            break;
        }
        mPatternsToDo.pop_front();
        if (pat.isEmpty()) {
            continue;
        }
        arguments << QLatin1String(pat);
        commandLineLength -= patLength + 1;
    }

    mProcess->setArguments(arguments);

    connect(mProcess, SIGNAL(finished(int,QProcess::ExitStatus)),
            SLOT(slotProcessExited(int,QProcess::ExitStatus)));
    connect(mProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        qCDebug(QGPGME_LOG) << "stdout:" << mProcess->readAllStandardOutput();
    });
    connect(mProcess, &QProcess::readyReadStandardError, this, [this]() {
        qCDebug(QGPGME_LOG) << "stderr:" << mProcess->readAllStandardError();
    });

    mProcess->start();
    if (!mProcess->waitForStarted()) {
        mError = GpgME::Error::fromCode(GPG_ERR_ENOENT, GPG_ERR_SOURCE_GPGSM);   // what else?
        deleteLater();
        return mError;
    } else {
        return GpgME::Error();
    }
}

void QGpgMERefreshSMIMEKeysJob::slotCancel()
{
    if (mProcess) {
        mProcess->kill();
    }
    mProcess = nullptr;
    mError = GpgME::Error::fromCode(GPG_ERR_CANCELED, GPG_ERR_SOURCE_GPGSM);
}

void QGpgMERefreshSMIMEKeysJob::slotStatus(QProcess *proc, const QString &type, const QStringList &args)
{
    if (proc != mProcess) {
        return;
    }
    QStringList::const_iterator it = args.begin();
    bool ok = false;

    if (type == QLatin1String("ERROR")) {

        if (args.size() < 2) {
            qCDebug(QGPGME_LOG) << "not recognising ERROR with < 2 args!";
            return;
        }
        const int source = (*++it).toInt(&ok);
        if (!ok) {
            qCDebug(QGPGME_LOG) << "expected number for first ERROR arg, got something else";
            return;
        }
        ok = false;
        const int code = (*++it).toInt(&ok);
        if (!ok) {
            qCDebug(QGPGME_LOG) << "expected number for second ERROR arg, got something else";
            return;
        }
        mError = GpgME::Error::fromCode(code, source);

    } else if (type == QLatin1String("PROGRESS")) {

        if (args.size() < 4) {
            qCDebug(QGPGME_LOG) << "not recognising PROGRESS with < 4 args!";
            return;
        }
        const QString what = *++it;
        ok = false;
        const int type = (*++it).toInt(&ok);
        if (!ok) {
            qCDebug(QGPGME_LOG) << "expected number for \"type\", got something else";
            return;
        }
        ok = false;
        const int cur = (*++it).toInt(&ok);
        if (!ok) {
            qCDebug(QGPGME_LOG) << "expected number for \"cur\", got something else";
            return;
        }
        ok = false;
        const int total = (*++it).toInt(&ok);
        if (!ok) {
            qCDebug(QGPGME_LOG) << "expected number for \"total\", got something else";
            return;
        }
        Q_EMIT jobProgress(cur, total);
        Q_EMIT rawProgress(what, type, cur, total);
        QT_WARNING_PUSH
        QT_WARNING_DISABLE_DEPRECATED
        Q_EMIT progress(what, cur, total);
        QT_WARNING_POP
    }
}

void QGpgMERefreshSMIMEKeysJob::slotProcessExited(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (!mError && !mPatternsToDo.empty()) {
        if (const GpgME::Error err = startAProcess()) {
            mError = err;
        } else {
            return;
        }
    }

    Q_EMIT done();
    if (!mError &&
            (exitStatus != QProcess::NormalExit || exitCode != 0)) {
        mError = GpgME::Error::fromCode(GPG_ERR_GENERAL, GPG_ERR_SOURCE_GPGSM);
    }
    Q_EMIT result(mError);
    deleteLater();
}
#include "qgpgmerefreshsmimekeysjob.moc"

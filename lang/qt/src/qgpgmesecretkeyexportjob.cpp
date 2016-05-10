/*
    qgpgmesecretexportjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klar�vdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

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

#include "qgpgmesecretkeyexportjob.h"

#include <QDebug>
#include "gpgme_backend_debug.h"

#include "context.h"
#include "data.h"

#include <QStringList>

#include <gpg-error.h>

#include <string.h>
#include <assert.h>

QGpgME::QGpgMESecretKeyExportJob::QGpgMESecretKeyExportJob(bool armour, const QString &charset)
    : ExportJob(0),
      mProcess(0),
      mError(0),
      mArmour(armour),
      mCharset(charset)
{

}

QGpgME::QGpgMESecretKeyExportJob::~QGpgMESecretKeyExportJob()
{

}

GpgME::Error QGpgME::QGpgMESecretKeyExportJob::start(const QStringList &patterns)
{
    assert(mKeyData.isEmpty());

    if (patterns.size() != 1 || patterns.front().isEmpty()) {
        deleteLater();
        return mError = GpgME::Error::fromCode(GPG_ERR_INV_VALUE, GPG_ERR_SOURCE_GPGSM);
    }

    // create and start gpgsm process:
    mProcess = new QProcess(this);
    mProcess->setObjectName(QStringLiteral("gpgsm --export-secret-key-p12"));

    // FIXME: obtain the path to gpgsm from gpgme, so we use the same instance.
    mProcess->setProgram("gpgsm");
    QStringList arguments;
    arguments << QStringLiteral("--export-secret-key-p12");
    if (mArmour) {
        arguments << QStringLiteral("--armor");
    }
    if (!mCharset.isEmpty()) {
        arguments << QStringLiteral("--p12-charset") << mCharset;
    }
    arguments << QLatin1String(patterns.front().toUtf8());

    mProcess->setArguments(arguments);
    connect(mProcess, SIGNAL(finished(int,QProcess::ExitStatus)),
            SLOT(slotProcessExited(int,QProcess::ExitStatus)));
    connect(mProcess, &QProcess::readyReadStandardOutput,
            this, &QGpgMESecretKeyExportJob::slotStdout);
    connect(mProcess, &QProcess::readyReadStandardError,
            this, &QGpgMESecretKeyExportJob::slotStderr);

    mProcess->start();
    if (!mProcess->waitForStarted()) {
        mError = GpgME::Error::fromCode(GPG_ERR_ENOENT, GPG_ERR_SOURCE_GPGSM);   // what else?
        deleteLater();
        return mError;
    } else {
        return GpgME::Error();
    }
}

void QGpgME::QGpgMESecretKeyExportJob::slotCancel()
{
    if (mProcess) {
        mProcess->kill();
    }
    mProcess = 0;
    mError = GpgME::Error::fromCode(GPG_ERR_CANCELED, GPG_ERR_SOURCE_GPGSM);
}

void QGpgME::QGpgMESecretKeyExportJob::slotStdout()
{
    QString line = QString::fromLocal8Bit(mProcess->readLine());
    if (!line.isEmpty()) {
        return;
    }
    const unsigned int oldlen = mKeyData.size();
    mKeyData.resize(oldlen + line.length());
    memcpy(mKeyData.data() + oldlen, line.toLatin1(), line.length());
}

void QGpgME::QGpgMESecretKeyExportJob::slotStderr()
{
    // implement? or not?
}

void QGpgME::QGpgMESecretKeyExportJob::slotProcessExited(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_EMIT done();
    if (!mError &&
            (exitStatus != QProcess::NormalExit || exitCode != 0)) {
        mError = GpgME::Error::fromCode(GPG_ERR_GENERAL, GPG_ERR_SOURCE_GPGSM);
    }
    Q_EMIT result(mError, mKeyData);
    deleteLater();
}
#include "qgpgmesecretkeyexportjob.moc"

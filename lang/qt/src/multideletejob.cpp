/*
    multideletejob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB

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

#include "multideletejob.h"
#include "protocol.h"
#include "deletejob.h"

#include <gpgme++/key.h>
#include <gpgme++/context.h>
#include <gpgme++/data.h>

#include <iterator>

#include <assert.h>

QGpgME::MultiDeleteJob::MultiDeleteJob(const Protocol *protocol)
    : Job(nullptr),
      mProtocol(protocol),
      mJob(nullptr)
{
    assert(protocol);
}

QGpgME::MultiDeleteJob::~MultiDeleteJob()
{

}

GpgME::Error QGpgME::MultiDeleteJob::start(const std::vector<GpgME::Key> &keys, bool allowSecretKeyDeletion)
{
    mKeys = keys;
    mAllowSecretKeyDeletion = allowSecretKeyDeletion;
    mIt = mKeys.begin();

    const GpgME::Error err = startAJob();

    if (err) {
        deleteLater();
    }
    return err;
}

void QGpgME::MultiDeleteJob::slotCancel()
{
    if (mJob) {
        mJob->slotCancel();
    }
    mIt = mKeys.end();
}

void QGpgME::MultiDeleteJob::slotResult(const GpgME::Error &err)
{
    mJob = nullptr;
    GpgME::Error error = err;
    if (error ||  // error in last op
            mIt == mKeys.end() || // (shouldn't happen)
            ++mIt == mKeys.end() || // was the last key
            (error = startAJob())) {  // error starting the job for the new key
        Q_EMIT done();
        Q_EMIT result(error, error && mIt != mKeys.end() ? *mIt : GpgME::Key::null);
        deleteLater();
        return;
    }

    const int current = mIt - mKeys.begin();
    const int total = mKeys.size();
    const QString what = QStringLiteral("%1/%2").arg(current).arg(total);
    Q_EMIT jobProgress(current, total);
    Q_EMIT rawProgress(what, '?', current, total);
    QT_WARNING_PUSH
    QT_WARNING_DISABLE_DEPRECATED
    Q_EMIT progress(what, current, total);
    QT_WARNING_POP
}

GpgME::Error QGpgME::MultiDeleteJob::startAJob()
{
    if (mIt == mKeys.end()) {
        return GpgME::Error(0);
    }
    mJob = mProtocol->deleteJob();
    assert(mJob);   // FIXME: we need a way to generate errors ourselves,
    // but I don't like the dependency on gpg-error :/

    connect(mJob.data(), &DeleteJob::result, this, &MultiDeleteJob::slotResult);

    return mJob->start(*mIt, mAllowSecretKeyDeletion);
}

#include "multideletejob.moc"

/* dataprovider.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (C) 2004 Klarävdalens Datakonsult AB
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
*/

// -*- c++ -*-

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <dataprovider.h>

#include <error.h>

#include <QIODevice>
#include <QProcess>

#include <cstdio>
#include <cstring>
#include <cassert>

using namespace QGpgME;
using namespace GpgME;

//
//
// QByteArrayDataProvider
//
//

static bool resizeAndInit(QByteArray &ba, size_t newSize)
{
    const size_t oldSize = ba.size();
    ba.resize(newSize);
    const bool ok = (newSize == static_cast<size_t>(ba.size()));
    if (ok) {
        memset(ba.data() + oldSize, 0, newSize - oldSize);
    }
    return ok;
}

QByteArrayDataProvider::QByteArrayDataProvider()
    : GpgME::DataProvider(), mOff(0) {}

QByteArrayDataProvider::QByteArrayDataProvider(const QByteArray &initialData)
    : GpgME::DataProvider(), mArray(initialData), mOff(0) {}

QByteArrayDataProvider::~QByteArrayDataProvider() {}

ssize_t QByteArrayDataProvider::read(void *buffer, size_t bufSize)
{
#ifndef NDEBUG
    //qDebug( "QByteArrayDataProvider::read( %p, %d )", buffer, bufSize );
#endif
    if (bufSize == 0) {
        return 0;
    }
    if (!buffer) {
        Error::setSystemError(GPG_ERR_EINVAL);
        return -1;
    }
    if (mOff >= mArray.size()) {
        return 0; // EOF
    }
    size_t amount = qMin(bufSize, static_cast<size_t>(mArray.size() - mOff));
    assert(amount > 0);
    memcpy(buffer, mArray.data() + mOff, amount);
    mOff += amount;
    return amount;
}

ssize_t QByteArrayDataProvider::write(const void *buffer, size_t bufSize)
{
#ifndef NDEBUG
    //qDebug( "QByteArrayDataProvider::write( %p, %lu )", buffer, static_cast<unsigned long>( bufSize ) );
#endif
    if (bufSize == 0) {
        return 0;
    }
    if (!buffer) {
        Error::setSystemError(GPG_ERR_EINVAL);
        return -1;
    }
    if (mOff >= mArray.size()) {
        resizeAndInit(mArray, mOff + bufSize);
    }
    if (mOff >= mArray.size()) {
        Error::setSystemError(GPG_ERR_EIO);
        return -1;
    }
    assert(bufSize <= static_cast<size_t>(mArray.size()) - mOff);
    memcpy(mArray.data() + mOff, buffer, bufSize);
    mOff += bufSize;
    return bufSize;
}

off_t QByteArrayDataProvider::seek(off_t offset, int whence)
{
#ifndef NDEBUG
    //qDebug( "QByteArrayDataProvider::seek( %d, %d )", int(offset), whence );
#endif
    int newOffset = mOff;
    switch (whence) {
    case SEEK_SET:
        newOffset = offset;
        break;
    case SEEK_CUR:
        newOffset += offset;
        break;
    case SEEK_END:
        newOffset = mArray.size() + offset;
        break;
    default:
        Error::setSystemError(GPG_ERR_EINVAL);
        return (off_t) - 1;
    }
    return mOff = newOffset;
}

void QByteArrayDataProvider::release()
{
#ifndef NDEBUG
    //qDebug( "QByteArrayDataProvider::release()" );
#endif
    mArray = QByteArray();
}

//
//
// QIODeviceDataProvider
//
//

QIODeviceDataProvider::QIODeviceDataProvider(const std::shared_ptr<QIODevice> &io)
    : GpgME::DataProvider(),
      mIO(io),
      mErrorOccurred(false),
      mHaveQProcess(qobject_cast<QProcess *>(io.get()))
{
    assert(mIO);
}

QIODeviceDataProvider::~QIODeviceDataProvider() {}

bool QIODeviceDataProvider::isSupported(Operation op) const
{
    const QProcess *const proc = qobject_cast<QProcess *>(mIO.get());
    bool canRead = true;
    if (proc) {
        canRead = proc->readChannel() == QProcess::StandardOutput;
    }

    switch (op) {
    case Read:    return mIO->isReadable() && canRead;
    case Write:   return mIO->isWritable();
    case Seek:    return !mIO->isSequential();
    case Release: return true;
    default:      return false;
    }
}

static qint64 blocking_read(const std::shared_ptr<QIODevice> &io, char *buffer, qint64 maxSize)
{
    while (!io->bytesAvailable()) {
        if (!io->waitForReadyRead(-1)) {
            if (const QProcess *const p = qobject_cast<QProcess *>(io.get())) {
                if (p->error() == QProcess::UnknownError &&
                        p->exitStatus() == QProcess::NormalExit &&
                        p->exitCode() == 0) {
                    if (io->atEnd()) {
                        // EOF
                        return 0;
                    } // continue reading even if process ended to ensure
                      // everything is read.
                } else {
                    Error::setSystemError(GPG_ERR_EIO);
                    return -1;
                }
            } else {
                return 0; // assume EOF (loses error cases :/ )
            }
        }
    }
    return io->read(buffer, maxSize);
}

ssize_t QIODeviceDataProvider::read(void *buffer, size_t bufSize)
{
#ifndef NDEBUG
    //qDebug( "QIODeviceDataProvider::read( %p, %lu )", buffer, bufSize );
#endif
    if (bufSize == 0) {
        return 0;
    }
    if (!buffer) {
        Error::setSystemError(GPG_ERR_EINVAL);
        return -1;
    }
    const qint64 numRead = mHaveQProcess
                           ? blocking_read(mIO, static_cast<char *>(buffer), bufSize)
                           : mIO->read(static_cast<char *>(buffer), bufSize);

    //workaround: some QIODevices (known example: QProcess) might not return 0 (EOF), but immediately -1 when finished. If no
    //errno is set, gpgme doesn't detect the error and loops forever. So return 0 on the very first -1 in case errno is 0

    ssize_t rc = numRead;
    if (numRead < 0 && !Error::hasSystemError()) {
        if (mErrorOccurred) {
            Error::setSystemError(GPG_ERR_EIO);
        } else {
            rc = 0;
        }
    }
    if (numRead < 0) {
        mErrorOccurred = true;
    }
    return rc;
}

ssize_t QIODeviceDataProvider::write(const void *buffer, size_t bufSize)
{
#ifndef NDEBUG
    //qDebug( "QIODeviceDataProvider::write( %p, %lu )", buffer, static_cast<unsigned long>( bufSize ) );
#endif
    if (bufSize == 0) {
        return 0;
    }
    if (!buffer) {
        Error::setSystemError(GPG_ERR_EINVAL);
        return -1;
    }

    ssize_t ret = mIO->write(static_cast<const char *>(buffer), bufSize);
    if (mHaveQProcess) {
        /* XXX: With at least Qt 5.12 we have the problem that the acutal write
         * would be triggered by an event / slot. So as we have moved the io
         * device to our thread this is never triggered until the job is finished
         * calling waitForBytesWritten internally triggers a _q_canWrite which will
         * actually write. This is what we want as we want to stream and not to
         * buffer endlessly. */
        qobject_cast<QProcess *>(mIO.get())->waitForBytesWritten(0);
    }
    return ret;
}

off_t QIODeviceDataProvider::seek(off_t offset, int whence)
{
#ifndef NDEBUG
    //qDebug( "QIODeviceDataProvider::seek( %d, %d )", int(offset), whence );
#endif
    if (mIO->isSequential()) {
        Error::setSystemError(GPG_ERR_ESPIPE);
        return (off_t) - 1;
    }
    qint64 newOffset = mIO->pos();
    switch (whence) {
    case SEEK_SET:
        newOffset = offset;
        break;
    case SEEK_CUR:
        newOffset += offset;
        break;
    case SEEK_END:
        newOffset = mIO->size() + offset;
        break;
    default:
        Error::setSystemError(GPG_ERR_EINVAL);
        return (off_t) - 1;
    }
    if (!mIO->seek(newOffset)) {
        Error::setSystemError(GPG_ERR_EINVAL);
        return (off_t) - 1;
    }
    return newOffset;
}

void QIODeviceDataProvider::release()
{
#ifndef NDEBUG
    //qDebug( "QIODeviceDataProvider::release()" );
#endif
    mIO->close();
}

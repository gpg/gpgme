/* dataprovider.cpp
   Copyright (C) 2004 Klar�vdalens Datakonsult AB

   This file is part of QGPGME.

   QGPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Library General Public License as published
   by the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   QGPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with QGPGME; see the file COPYING.LIB.  If not, write to the
   Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA. */

// -*- c++ -*-

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

QIODeviceDataProvider::QIODeviceDataProvider(const boost::shared_ptr<QIODevice> &io)
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

static qint64 blocking_read(const boost::shared_ptr<QIODevice> &io, char *buffer, qint64 maxSize)
{
    while (!io->bytesAvailable()) {
        if (!io->waitForReadyRead(-1)) {
            if (const QProcess *const p = qobject_cast<QProcess *>(io.get())) {
                if (p->error() == QProcess::UnknownError &&
                        p->exitStatus() == QProcess::NormalExit &&
                        p->exitCode() == 0) {
                    return 0;
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

    return mIO->write(static_cast<const char *>(buffer), bufSize);
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

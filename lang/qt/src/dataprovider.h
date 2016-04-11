/* dataprovider.h
   Copyright (C) 2004 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 Intevation GmbH

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
#ifndef __QGPGME_DATAPROVIDER_H__
#define __QGPGME_DATAPROVIDER_H__

#include "qgpgme_export.h"
#include <interfaces/dataprovider.h>
#include <memory>

#include <QtCore/QByteArray>


class QIODevice;

namespace QGpgME
{

class QGPGME_EXPORT QByteArrayDataProvider : public GpgME::DataProvider
{
public:
    QByteArrayDataProvider();
    explicit QByteArrayDataProvider(const QByteArray &initialData);
    ~QByteArrayDataProvider();

    const QByteArray &data() const
    {
        return mArray;
    }

private:
    // these shall only be accessed through the dataprovider
    // interface, where they're public:
    /*! \reimp */
    bool isSupported(Operation) const
    {
        return true;
    }
    /*! \reimp */
    ssize_t read(void *buffer, size_t bufSize);
    /*! \reimp */
    ssize_t write(const void *buffer, size_t bufSize);
    /*! \reimp */
    off_t seek(off_t offset, int whence);
    /*! \reimp */
    void release();

private:
    QByteArray mArray;
    off_t mOff;
};

class QGPGME_EXPORT QIODeviceDataProvider : public GpgME::DataProvider
{
public:
    explicit QIODeviceDataProvider(const std::shared_ptr<QIODevice> &initialData);
    ~QIODeviceDataProvider();

    const std::shared_ptr<QIODevice> &ioDevice() const
    {
        return mIO;
    }

private:
    // these shall only be accessed through the dataprovider
    // interface, where they're public:
    /*! \reimp */
    bool isSupported(Operation) const;
    /*! \reimp */
    ssize_t read(void *buffer, size_t bufSize);
    /*! \reimp */
    ssize_t write(const void *buffer, size_t bufSize);
    /*! \reimp */
    off_t seek(off_t offset, int whence);
    /*! \reimp */
    void release();

private:
    const std::shared_ptr<QIODevice> mIO;
    bool mErrorOccurred : 1;
    bool mHaveQProcess  : 1;
};

} // namespace QGpgME

#endif

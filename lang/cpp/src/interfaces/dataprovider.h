/*
  interface/dataprovider.h - Interface for data sources
  Copyright (C) 2003 Klarälvdalens Datakonsult AB

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

#ifndef __GPGMEPP_INTERFACES_DATAPROVIDER_H__
#define __GPGMEPP_INTERFACES_DATAPROVIDER_H__

#include <sys/types.h>

#include "gpgmepp_export.h"

#include <gpg-error.h>

namespace GpgME
{

class GPGMEPP_EXPORT DataProvider
{
public:
    virtual ~DataProvider() {}

    enum Operation {
        Read, Write, Seek, Release
    };
    virtual bool isSupported(Operation op) const = 0;

    virtual ssize_t read(void   *buffer, size_t bufSize) = 0;
    virtual ssize_t write(const void *buffer, size_t bufSize) = 0;
    virtual off_t seek(off_t offset, int whence) = 0;
    virtual void release() = 0;
};

} // namespace GpgME

#endif // __GPGMEPP_INTERFACES_DATAPROVIDER_H__

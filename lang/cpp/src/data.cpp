/*
  data.cpp - wraps a gpgme data object
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

#include <config-gpgme++.h>

#include "data_p.h"
#include <error.h>
#include <interfaces/dataprovider.h>

#include <gpgme.h>

#ifndef NDEBUG
#include <iostream>
#endif

GpgME::Data::Private::~Private()
{
    if (data) {
        gpgme_data_release(data);
    }
}

const GpgME::Data::Null GpgME::Data::null;

GpgME::Data::Data()
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new(&data);
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(const Null &)
    : d(new Private(0))
{

}

GpgME::Data::Data(gpgme_data_t data)
    : d(new Private(data))
{

}

GpgME::Data::Data(const char *buffer, size_t size, bool copy)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_mem(&data, buffer, size, int(copy));
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(const char *filename)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new(&data);
    d.reset(new Private(e ? 0 : data));
    if (!e) {
        setFileName(filename);
    }
}

GpgME::Data::Data(const char *filename, off_t offset, size_t length)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_filepart(&data, filename, 0, offset, length);
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(FILE *fp)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_stream(&data, fp);
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(FILE *fp, off_t offset, size_t length)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_filepart(&data, 0, fp, offset, length);
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(int fd)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_fd(&data, fd);
    d.reset(new Private(e ? 0 : data));
}

GpgME::Data::Data(DataProvider *dp)
{
    d.reset(new Private);
    if (!dp) {
        return;
    }
    if (!dp->isSupported(DataProvider::Read)) {
        d->cbs.read = 0;
    }
    if (!dp->isSupported(DataProvider::Write)) {
        d->cbs.write = 0;
    }
    if (!dp->isSupported(DataProvider::Seek)) {
        d->cbs.seek = 0;
    }
    if (!dp->isSupported(DataProvider::Release)) {
        d->cbs.release = 0;
    }
    const gpgme_error_t e = gpgme_data_new_from_cbs(&d->data, &d->cbs, dp);
    if (e) {
        d->data = 0;
    }
#ifndef NDEBUG
    //std::cerr << "GpgME::Data(): DataProvider supports: "
    //    << ( d->cbs.read ? "read" : "no read" ) << ", "
    //    << ( d->cbs.write ? "write" : "no write" ) << ", "
    //    << ( d->cbs.seek ? "seek" : "no seek" ) << ", "
    //    << ( d->cbs.release ? "release" : "no release" ) << std::endl;
#endif
}

bool GpgME::Data::isNull() const
{
    return !d || !d->data;
}

GpgME::Data::Encoding GpgME::Data::encoding() const
{
    switch (gpgme_data_get_encoding(d->data)) {
    case GPGME_DATA_ENCODING_NONE:   return AutoEncoding;
    case GPGME_DATA_ENCODING_BINARY: return BinaryEncoding;
    case GPGME_DATA_ENCODING_BASE64: return Base64Encoding;
    case GPGME_DATA_ENCODING_ARMOR:  return ArmorEncoding;
    }
    return AutoEncoding;
}

GpgME::Error GpgME::Data::setEncoding(Encoding enc)
{
    gpgme_data_encoding_t ge = GPGME_DATA_ENCODING_NONE;
    switch (enc) {
    case AutoEncoding:   ge = GPGME_DATA_ENCODING_NONE;   break;
    case BinaryEncoding: ge = GPGME_DATA_ENCODING_BINARY; break;
    case Base64Encoding: ge = GPGME_DATA_ENCODING_BASE64; break;
    case ArmorEncoding:  ge = GPGME_DATA_ENCODING_ARMOR;  break;
    }
    return Error(gpgme_data_set_encoding(d->data, ge));
}

char *GpgME::Data::fileName() const
{
#ifdef HAVE_GPGME_DATA_SET_FILE_NAME
    return gpgme_data_get_file_name(d->data);
#else
    return 0;
#endif
}

GpgME::Error GpgME::Data::setFileName(const char *name)
{
#ifdef HAVE_GPGME_DATA_SET_FILE_NAME
    return Error(gpgme_data_set_file_name(d->data, name));
#else
    (void)name;
    return Error();
#endif
}

ssize_t GpgME::Data::read(void *buffer, size_t length)
{
    return gpgme_data_read(d->data, buffer, length);
}

ssize_t GpgME::Data::write(const void *buffer, size_t length)
{
    return gpgme_data_write(d->data, buffer, length);
}

off_t GpgME::Data::seek(off_t offset, int whence)
{
    return gpgme_data_seek(d->data, offset, whence);
}

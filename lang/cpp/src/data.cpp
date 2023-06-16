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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "data_p.h"
#include "context_p.h"
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
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(const Null &)
    : d(new Private(nullptr))
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
    std::string sizestr = std::to_string(size);
    // Ignore errors as this is optional
    gpgme_data_set_flag(data, "size-hint", sizestr.c_str());
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(const char *filename)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new(&data);
    d.reset(new Private(e ? nullptr : data));
    if (!e) {
        setFileName(filename);
    }
}

GpgME::Data::Data(const char *filename, off_t offset, size_t length)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_filepart(&data, filename, nullptr, offset, length);
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(FILE *fp)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_stream(&data, fp);
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(FILE *fp, off_t offset, size_t length)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_filepart(&data, nullptr, fp, offset, length);
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(int fd)
{
    gpgme_data_t data;
    const gpgme_error_t e = gpgme_data_new_from_fd(&data, fd);
    d.reset(new Private(e ? nullptr : data));
}

GpgME::Data::Data(DataProvider *dp)
{
    d.reset(new Private);
    if (!dp) {
        return;
    }
    if (!dp->isSupported(DataProvider::Read)) {
        d->cbs.read = nullptr;
    }
    if (!dp->isSupported(DataProvider::Write)) {
        d->cbs.write = nullptr;
    }
    if (!dp->isSupported(DataProvider::Seek)) {
        d->cbs.seek = nullptr;
    }
    if (!dp->isSupported(DataProvider::Release)) {
        d->cbs.release = nullptr;
    }
    const gpgme_error_t e = gpgme_data_new_from_cbs(&d->data, &d->cbs, dp);
    if (e) {
        d->data = nullptr;
    }
    if (dp->isSupported(DataProvider::Seek)) {
        off_t size = seek(0, SEEK_END);
        seek(0, SEEK_SET);
        std::string sizestr = std::to_string(size);
        // Ignore errors as this is optional
        gpgme_data_set_flag(d->data, "size-hint", sizestr.c_str());
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
    case GPGME_DATA_ENCODING_MIME:   return MimeEncoding;
    case GPGME_DATA_ENCODING_URL:    return UrlEncoding;
    case GPGME_DATA_ENCODING_URLESC: return UrlEscEncoding;
    case GPGME_DATA_ENCODING_URL0:   return Url0Encoding;
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
    case MimeEncoding:   ge = GPGME_DATA_ENCODING_MIME;  break;
    case UrlEncoding:    ge = GPGME_DATA_ENCODING_URL; break;
    case UrlEscEncoding: ge = GPGME_DATA_ENCODING_URLESC; break;
    case Url0Encoding:   ge = GPGME_DATA_ENCODING_URL0; break;
    }
    return Error(gpgme_data_set_encoding(d->data, ge));
}

GpgME::Data::Type GpgME::Data::type() const
{
    if (isNull()) {
        return Invalid;
    }
    switch (gpgme_data_identify(d->data, 0)) {
    case GPGME_DATA_TYPE_INVALID:       return Invalid;
    case GPGME_DATA_TYPE_UNKNOWN:       return Unknown;
    case GPGME_DATA_TYPE_PGP_SIGNED:    return PGPSigned;
    case GPGME_DATA_TYPE_PGP_OTHER:     return PGPOther;
    case GPGME_DATA_TYPE_PGP_KEY:       return PGPKey;
    case GPGME_DATA_TYPE_CMS_SIGNED:    return CMSSigned;
    case GPGME_DATA_TYPE_CMS_ENCRYPTED: return CMSEncrypted;
    case GPGME_DATA_TYPE_CMS_OTHER:     return CMSOther;
    case GPGME_DATA_TYPE_X509_CERT:     return X509Cert;
    case GPGME_DATA_TYPE_PKCS12:        return PKCS12;
    case GPGME_DATA_TYPE_PGP_ENCRYPTED: return PGPEncrypted;
    case GPGME_DATA_TYPE_PGP_SIGNATURE: return PGPSignature;
    }
    return Invalid;
}

char *GpgME::Data::fileName() const
{
    return gpgme_data_get_file_name(d->data);
}

GpgME::Error GpgME::Data::setFileName(const char *name)
{
    return Error(gpgme_data_set_file_name(d->data, name));
}

GpgME::Error GpgME::Data::setFileName(const std::string &name)
{
    return Error(gpgme_data_set_file_name(d->data, name.c_str()));
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

GpgME::Error GpgME::Data::rewind()
{
    return Error(gpgme_data_rewind(d->data));
}

std::vector<GpgME::Key> GpgME::Data::toKeys(Protocol proto) const
{
    std::vector<GpgME::Key> ret;
    if (isNull()) {
        return ret;
    }
    auto ctx = GpgME::Context::createForProtocol(proto);
    if (!ctx) {
        return ret;
    }

    if (gpgme_op_keylist_from_data_start (ctx->impl()->ctx, d->data, 0)) {
        return ret;
    }

    gpgme_key_t key;
    while (!gpgme_op_keylist_next (ctx->impl()->ctx, &key)) {
        ret.push_back(GpgME::Key(key, false));
    }
    gpgme_data_seek (d->data, 0, SEEK_SET);

    delete ctx;
    return ret;
}

std::string GpgME::Data::toString()
{
  std::string ret;
  char buf[4096];
  size_t nread;
  seek (0, SEEK_SET);
  while ((nread = read (buf, 4096)) > 0)
    {
      ret += std::string (buf, nread);
    }
  seek (0, SEEK_SET);
  return ret;
}

GpgME::Error GpgME::Data::setFlag(const char *name, const char *value)
{
    return Error(gpgme_data_set_flag(d->data, name, value));
}

GpgME::Error GpgME::Data::setSizeHint(uint64_t size)
{
    const std::string val = std::to_string(size);
    return Error(gpgme_data_set_flag(d->data, "size-hint", val.c_str()));
}

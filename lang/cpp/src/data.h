/*
  data.h - wraps a gpgme data object
  Copyright (C) 2003,2004 Klarälvdalens Datakonsult AB

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

#ifndef __GPGMEPP_DATA_H__
#define __GPGMEPP_DATA_H__

#include "global.h"
#include "key.h"

#include <sys/types.h> // for size_t, off_t
#include <cstdio> // FILE
#include <algorithm>
#include <memory>

namespace GpgME
{

class DataProvider;
class Error;

class GPGMEPP_EXPORT Data
{
    struct Null {
		Null() {}
	};
public:
    /* implicit */ Data(const Null &);
    Data();
    explicit Data(gpgme_data_t data);

    // Memory-Based Data Buffers:
    Data(const char *buffer, size_t size, bool copy = true);
    explicit Data(const char *filename);
    Data(const char *filename, off_t offset, size_t length);
    Data(std::FILE *fp, off_t offset, size_t length);
    // File-Based Data Buffers:
    explicit Data(std::FILE *fp);
    explicit Data(int fd);
    // Callback-Based Data Buffers:
    explicit Data(DataProvider *provider);

    static const Null null;

    const Data &operator=(Data other)
    {
        swap(other);
        return *this;
    }

    void swap(Data &other)
    {
        using std::swap;
        swap(this->d, other.d);
    }

    bool isNull() const;

    enum Encoding {
        AutoEncoding,
        BinaryEncoding,
        Base64Encoding,
        ArmorEncoding,
        MimeEncoding,
        UrlEncoding,
        UrlEscEncoding,
        Url0Encoding,
    };
    Encoding encoding() const;
    Error setEncoding(Encoding encoding);

    enum Type {
        Invalid,
        Unknown,
        PGPSigned,
        PGPOther,
        PGPKey,
        CMSSigned,
        CMSEncrypted,
        CMSOther,
        X509Cert,
        PKCS12,
        PGPEncrypted,
        PGPSignature,
    };
    Type type() const;

    char *fileName() const;
    Error setFileName(const char *name);

    ssize_t read(void *buffer, size_t length);
    ssize_t write(const void *buffer, size_t length);
    off_t seek(off_t offset, int whence);

    /* Convenience function to do a seek (0, SEEK_SET).  */
    Error rewind();

    /** Try to parse the data to a key object using the
     * Protocol proto. Returns an empty list on error.*/
    std::vector<Key> toKeys(const Protocol proto = Protocol::OpenPGP) const;

    /** Return a copy of the data as std::string. Sets seek pos to 0 */
    std::string toString();

    class Private;
    Private *impl()
    {
        return d.get();
    }
    const Private *impl() const
    {
        return d.get();
    }
private:
    std::shared_ptr<Private> d;
};

}

GPGMEPP_MAKE_STD_SWAP_SPECIALIZATION(Data)

#endif // __GPGMEPP_DATA_H__

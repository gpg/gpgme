/*
    filelistdataprovider.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2023 g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "filelistdataprovider.h"

#include "dataprovider.h"

#include <QString>

#include <gpgme++/error.h>

#include <numeric>

using namespace QGpgME;
using namespace GpgME;

static QByteArray encodeFilenames(const std::vector<QString> &filenames)
{
    QByteArray ret;
    if (filenames.empty()) {
        return ret;
    }
    // calculate and reserve the needed minimum size of the result
    const auto addSize = [](unsigned int n, const QString &s) { return n + s.size(); };
    const unsigned int minSize = filenames.size()
        + std::accumulate(filenames.cbegin(), filenames.cend(), 0u, addSize);
    ret.reserve(minSize);
    // pack the filenames into the byte array
    for (const auto &f : filenames) {
        if (!f.isEmpty()) {
            ret += f.toUtf8() + '\0';
        }
    }
    ret.chop(1); // remove the trailing nul
    return ret;
}

FileListDataProvider::FileListDataProvider(const std::vector<QString> &filenames)
    : mProvider{new QByteArrayDataProvider{encodeFilenames(filenames)}}
{
}

FileListDataProvider::~FileListDataProvider() = default;

ssize_t FileListDataProvider::read(void* buffer, size_t bufSize)
{
    return mProvider->read(buffer, bufSize);
}

ssize_t FileListDataProvider::write(const void *, size_t)
{
    Error::setSystemError(GPG_ERR_EBADF);
    return -1;
}

off_t FileListDataProvider::seek(off_t offset, int whence)
{
    return mProvider->seek(offset, whence);
}

void FileListDataProvider::release()
{
    mProvider->release();
}

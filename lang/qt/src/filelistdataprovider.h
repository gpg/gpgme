/*
    filelistdataprovider.h

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

#ifndef __QGPGME_FILELISTDATAPROVIDER_H__
#define __QGPGME_FILELISTDATAPROVIDER_H__

#include "qgpgme_export.h"

#ifdef BUILDING_QGPGME
#include <interfaces/dataprovider.h>
#else
#include <gpgme++/interfaces/dataprovider.h>
#endif

#include <memory>
#include <vector>

class QString;

namespace QGpgME
{

/**
 * This read-only data provider simplifies providing a nul-separated list of
 * UTF-8-encoded filenames, e.g. for creating signed or encrypted archives.
 */
class QGPGME_EXPORT FileListDataProvider : public GpgME::DataProvider
{
public:
    explicit FileListDataProvider(const std::vector<QString> &filenames);
    ~FileListDataProvider() override;

private:
    bool isSupported(Operation op) const override
    {
        return op != Operation::Write;
    }
    ssize_t read(void *buffer, size_t bufSize) override;
    ssize_t write(const void *buffer, size_t bufSize) override;
    off_t seek(off_t offset, int whence) override;
    void release() override;

private:
    std::unique_ptr<GpgME::DataProvider> mProvider;
};

}

#endif // __QGPGME_FILELISTDATAPROVIDER_H__

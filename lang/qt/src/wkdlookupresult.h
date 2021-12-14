/*
    wkdlookupresult.h - wraps the result of a WKDLookupJob

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2021 g10 Code GmbH
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

#ifndef __QGPGME_WKDLOOKUPRESULT_H__
#define __QGPGME_WKDLOOKUPRESULT_H__

#include "qgpgme_export.h"

#include <gpgme++/result.h>

#include <memory>

namespace GpgME
{
class Data;
class Error;
}

namespace QGpgME
{

class QGPGME_EXPORT WKDLookupResult : public GpgME::Result
{
public:
    WKDLookupResult();
    ~WKDLookupResult();

    explicit WKDLookupResult(const std::string &pattern, const GpgME::Error &err);
    explicit WKDLookupResult(const std::string &pattern, const GpgME::Data &keyData, const std::string &source, const GpgME::Error &err);

    WKDLookupResult(const WKDLookupResult &other);
    WKDLookupResult &operator=(const WKDLookupResult &other);

    WKDLookupResult(WKDLookupResult &&other);
    WKDLookupResult &operator=(WKDLookupResult &&other);

    void swap(WKDLookupResult &other) noexcept;

    bool isNull() const;

    std::string pattern() const;
    GpgME::Data keyData() const;
    std::string source() const;

private:
    class Private;
    std::unique_ptr<Private> d;
};

QGPGME_EXPORT void swap(WKDLookupResult &a, WKDLookupResult &b);

}

#endif // __QGPGME_WKDLOOKUPRESULT_H__

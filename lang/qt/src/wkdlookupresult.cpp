/*
    wkdlookupresult.cpp - wraps the result of a WKDLookupJob

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "wkdlookupresult.h"

#include <gpgme++/data.h>

using namespace QGpgME;
using namespace GpgME;

class WKDLookupResult::Private
{
public:
    std::string pattern;
    GpgME::Data keyData;
    std::string source;
};

WKDLookupResult::WKDLookupResult() = default;

WKDLookupResult::~WKDLookupResult() = default;

WKDLookupResult::WKDLookupResult(const std::string &pattern, const Error &error)
    : Result{error}
    , d{new Private{pattern, {}, {}}}
{
}

WKDLookupResult::WKDLookupResult(const std::string &pattern, const Data &keyData, const std::string &source, const Error &error)
    : Result{error}
    , d{new Private{pattern, keyData, source}}
{
}

WKDLookupResult::WKDLookupResult(const WKDLookupResult &other)
    : Result{other}
{
    if (other.d) {
        d.reset(new Private{*other.d});
    }
}

WKDLookupResult &WKDLookupResult::operator=(const WKDLookupResult &other)
{
    auto tmp = other;
    swap(tmp);
    return *this;
}

WKDLookupResult::WKDLookupResult(WKDLookupResult &&other) = default;

WKDLookupResult &WKDLookupResult::operator=(WKDLookupResult &&other) = default;

void WKDLookupResult::swap(WKDLookupResult &other) noexcept
{
    Result::swap(other);
    std::swap(this->d, other.d);
}

bool WKDLookupResult::isNull() const
{
    return !d && !bool(error());
}

std::string WKDLookupResult::pattern() const
{
    return d ? d->pattern : std::string{};
}

Data WKDLookupResult::keyData() const
{
    return d ? d->keyData : Data{};
}

std::string WKDLookupResult::source() const
{
    return d ? d->source : std::string{};
}

void QGpgME::swap(WKDLookupResult &a, WKDLookupResult &b)
{
    a.swap(b);
}

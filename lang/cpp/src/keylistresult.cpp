/*
  keylistresult.cpp - wraps a gpgme keylist result
  Copyright (C) 2004 Klarälvdalens Datakonsult AB

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

#include <keylistresult.h>
#include "result_p.h"

#include <gpgme.h>

#include <cstring>
#include <cassert>

class GpgME::KeyListResult::Private
{
public:
    Private(const _gpgme_op_keylist_result &r) : res(r) {}
    Private(const Private &other) : res(other.res) {}

    _gpgme_op_keylist_result res;
};

GpgME::KeyListResult::KeyListResult(gpgme_ctx_t ctx, int error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

GpgME::KeyListResult::KeyListResult(gpgme_ctx_t ctx, const Error &error)
    : GpgME::Result(error), d()
{
    init(ctx);
}

void GpgME::KeyListResult::init(gpgme_ctx_t ctx)
{
    if (!ctx) {
        return;
    }
    gpgme_keylist_result_t res = gpgme_op_keylist_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(*res));
}

GpgME::KeyListResult::KeyListResult(const Error &error, const _gpgme_op_keylist_result &res)
    : GpgME::Result(error), d(new Private(res))
{

}

make_standard_stuff(KeyListResult)

void GpgME::KeyListResult::detach()
{
    if (!d || d.unique()) {
        return;
    }
    d.reset(new Private(*d));
}

void GpgME::KeyListResult::mergeWith(const KeyListResult &other)
{
    if (other.isNull()) {
        return;
    }
    if (isNull()) {   // just assign
        operator=(other);
        return;
    }
    // merge the truncated flag (try to keep detaching to a minimum):
    if (other.isTruncated() && !this->isTruncated()) {
        assert(other.d);
        detach();
        if (!d) {
            d.reset(new Private(*other.d));
        } else {
            d->res.truncated = true;
        }
    }
    if (! bool(error())) {    // only merge the error when there was none yet.
        Result::operator=(other);
    }
}

bool GpgME::KeyListResult::isTruncated() const
{
    return d && d->res.truncated;
}

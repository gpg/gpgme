/*
  assuanresult.cpp - wraps a gpgme assuan result
  Copyright (C) 2009 Klarälvdalens Datakonsult AB

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

#include <assuanresult.h>
#include "result_p.h"

#include <gpgme.h>

#include <istream>

using namespace GpgME;

#ifdef HAVE_GPGME_ASSUAN_ENGINE
class AssuanResult::Private
{
public:
    explicit Private(const gpgme_assuan_result_t r)
    {
        if (!r) {
            return;
        }
        error = r->err;
    }

    gpgme_error_t error;
};
#endif

AssuanResult::AssuanResult(gpgme_ctx_t ctx, int error)
    : Result(error), d()
{
    init(ctx);
}

AssuanResult::AssuanResult(gpgme_ctx_t ctx, const Error &error)
    : Result(error), d()
{
    init(ctx);
}

void AssuanResult::init(gpgme_ctx_t ctx)
{
    (void)ctx;
#ifdef HAVE_GPGME_ASSUAN_ENGINE
    if (!ctx) {
        return;
    }
    gpgme_assuan_result_t res = gpgme_op_assuan_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(res));
#endif
}

make_standard_stuff(AssuanResult)

Error AssuanResult::assuanError() const
{
#ifdef HAVE_GPGME_ASSUAN_ENGINE
    if (d) {
        return Error(d->error);
    }
#endif
    return Error();
}

std::ostream &GpgME::operator<<(std::ostream &os, const AssuanResult &result)
{
    os << "GpgME::AssuanResult(";
    if (!result.isNull()) {
        os << "\n error:       " << result.error()
           << "\n assuanError: " << result.assuanError()
           << "\n";
    }
    return os << ')';
}

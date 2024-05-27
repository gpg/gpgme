/*
  vfsmountresult.cpp - wraps a gpgme vfs mount result
  Copyright (C) 2009 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH <info@kdab.com>
  Author: Marc Mutz <marc@kdab.com>, Volker Krause <volker@kdab.com>

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

#include <vfsmountresult.h>
#include "result_p.h"

#include <gpgme.h>

#include <istream>
#include <string.h>

using namespace GpgME;

class VfsMountResult::Private
{
public:
    explicit Private(const gpgme_vfs_mount_result_t r) : mountDir(nullptr)
    {
        if (r && r->mount_dir) {
            mountDir = strdup(r->mount_dir);
        }
    }

    ~Private()
    {
        std::free(mountDir);
    }

    char *mountDir;
};

VfsMountResult::VfsMountResult(gpgme_ctx_t ctx, const Error &error, const Error &opError)
    : Result(error ? error : opError), d()
{
    init(ctx);
}

void VfsMountResult::init(gpgme_ctx_t ctx)
{
    (void)ctx;
    if (!ctx) {
        return;
    }
    gpgme_vfs_mount_result_t res = gpgme_op_vfs_mount_result(ctx);
    if (!res) {
        return;
    }
    d.reset(new Private(res));
}

make_standard_stuff(VfsMountResult)

const char *VfsMountResult::mountDir() const
{
    if (d) {
        return d->mountDir;
    }
    return nullptr;
}

std::ostream &GpgME::operator<<(std::ostream &os, const VfsMountResult &result)
{
    os << "GpgME::VfsMountResult(";
    if (!result.isNull()) {
        os << "\n error:       " << result.error()
           << "\n mount dir: " << result.mountDir()
           << "\n";
    }
    return os << ')';
}

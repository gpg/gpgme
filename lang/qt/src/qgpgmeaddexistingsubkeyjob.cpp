/*
    qgpgmeaddexistingsubkeyjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#include "qgpgmeaddexistingsubkeyjob.h"

#include "dataprovider.h"

#include <QDateTime>

#include "context.h"
#include "data.h"
#include "gpgaddexistingsubkeyeditinteractor.h"
#include "key.h"

#include <gpg-error.h>

using namespace QGpgME;
using namespace GpgME;

QGpgMEAddExistingSubkeyJob::QGpgMEAddExistingSubkeyJob(Context *context)
    : mixin_type{context}
{
    lateInitialization();
}

QGpgMEAddExistingSubkeyJob::~QGpgMEAddExistingSubkeyJob() = default;

static QGpgMEAddExistingSubkeyJob::result_type add_subkey(Context *ctx, const Key &key, const Subkey &subkey)
{
    std::unique_ptr<GpgAddExistingSubkeyEditInteractor> interactor{new GpgAddExistingSubkeyEditInteractor{subkey.keyGrip()}};

    if (!subkey.neverExpires()) {
        const auto expiry = QDateTime::fromSecsSinceEpoch(uint_least32_t(subkey.expirationTime()),
                                                          Qt::UTC).toString(u"yyyyMMdd'T'hhmmss").toStdString();
        interactor->setExpiry(expiry);
    }

    QGpgME::QByteArrayDataProvider dp;
    Data data(&dp);
    assert(!data.isNull());

    ctx->setFlag("extended-edit", "1");

    const Error err = ctx->edit(key, std::unique_ptr<EditInteractor>(interactor.release()), data);
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(err, log, ae);
}

Error QGpgMEAddExistingSubkeyJob::start(const GpgME::Key &key, const GpgME::Subkey &subkey)
{
    run(std::bind(&add_subkey, std::placeholders::_1, key, subkey));
    return {};
}

Error QGpgMEAddExistingSubkeyJob::exec(const GpgME::Key &key, const GpgME::Subkey &subkey)
{
    const result_type r = add_subkey(context(), key, subkey);
    return std::get<0>(r);
}

#include "qgpgmeaddexistingsubkeyjob.moc"

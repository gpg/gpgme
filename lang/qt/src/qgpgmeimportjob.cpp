/*
    qgpgmeimportjob.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004,2008 Klarälvdalens Datakonsult AB
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
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

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

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

#include "qgpgmeimportjob.h"

#include "importjob_p.h"

#include "dataprovider.h"

#include <context.h>
#include <data.h>
#include <key.h>

using namespace QGpgME;
using namespace GpgME;

namespace
{

class QGpgMEImportJobPrivate : public ImportJobPrivate
{
    QGpgMEImportJob *q = nullptr;

public:
    QGpgMEImportJobPrivate(QGpgMEImportJob *qq)
        : q{qq}
    {
    }

    ~QGpgMEImportJobPrivate() override = default;

private:
    GpgME::Error startIt() override
    {
        Q_ASSERT(!"Not supported by this Job class.");
        return Error::fromCode(GPG_ERR_NOT_SUPPORTED);
    }

    void startNow() override
    {
        q->run();
    }
};

}

QGpgMEImportJob::QGpgMEImportJob(Context *context)
    : mixin_type(context)
{
    setJobPrivate(this, std::unique_ptr<QGpgMEImportJobPrivate>{new QGpgMEImportJobPrivate{this}});
    lateInitialization();
}

QGpgMEImportJob::~QGpgMEImportJob() = default;

static const char *originToString(Key::Origin origin)
{
    static const std::map<Key::Origin, const char *> mapping = {
        { Key::OriginUnknown, "unknown" },
        { Key::OriginKS,      "ks" },
        { Key::OriginDane,    "dane" },
        { Key::OriginWKD,     "wkd" },
        { Key::OriginURL,     "url" },
        { Key::OriginFile,    "file" },
        { Key::OriginSelf,    "self" },
    };
    const auto it = mapping.find(origin);
    return (it != std::end(mapping)) ? it->second : nullptr;
}

static QGpgMEImportJob::result_type import_qba(Context *ctx, const QByteArray &certData, const QString &importFilter,
                                               Key::Origin keyOrigin, const QString &keyOriginUrl)
{
    if (!importFilter.isEmpty()) {
        ctx->setFlag("import-filter", importFilter.toStdString().c_str());
    }
    if (keyOrigin != Key::OriginUnknown) {
        if (const auto origin = originToString(keyOrigin)) {
            std::string value{origin};
            if (!keyOriginUrl.isEmpty()) {
                value += ",";
                value += keyOriginUrl.toStdString();
            }
            ctx->setFlag("key-origin", value.c_str());
        }
    }

    QGpgME::QByteArrayDataProvider dp(certData);
    Data data(&dp);

    ImportResult res = ctx->importKeys(data);
    // HACK: If the import failed with an error, then check if res.imports()
    // contains only import statuses with "bad passphrase" error; if yes, this
    // means that the user probably entered a wrong password to decrypt an
    // encrypted key for import. In this case, return a result with "bad
    // passphrase" error instead of the original error.
    // We check if all import statuses instead of any import status has a
    // "bad passphrase" error to avoid breaking imports that partially worked.
    // See https://dev.gnupg.org/T5713.
    const auto imports = res.imports();
    if (res.error() && !imports.empty()
        && std::all_of(std::begin(imports), std::end(imports),
                       [](const Import &import) {
                           return import.error().code() == GPG_ERR_BAD_PASSPHRASE;
                       })) {
        res = ImportResult{Error{GPG_ERR_BAD_PASSPHRASE}};
    }
    Error ae;
    const QString log = _detail::audit_log_as_html(ctx, ae);
    return std::make_tuple(res, log, ae);
}

Error QGpgMEImportJob::start(const QByteArray &certData)
{
    run(std::bind(&import_qba, std::placeholders::_1, certData, importFilter(), keyOrigin(), keyOriginUrl()));
    return Error();
}

GpgME::ImportResult QGpgME::QGpgMEImportJob::exec(const QByteArray &keyData)
{
    const result_type r = import_qba(context(), keyData, importFilter(), keyOrigin(), keyOriginUrl());
    return std::get<0>(r);
}

Error QGpgMEImportJob::startLater(const QByteArray &certData)
{
    setWorkerFunction(std::bind(&import_qba, std::placeholders::_1, certData, importFilter(), keyOrigin(), keyOriginUrl()));
    return {};
}

#include "qgpgmeimportjob.moc"

/*
    run-refreshkeysjob.cpp

    This file is part of QGpgME's test suite.
    Copyright (c) 2022 by g10 Code GmbH
    Software engineering by Ingo Klöcker <dev@ingo-kloecker.de>

    QGpgME is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License,
    version 2, as published by the Free Software Foundation.

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

#include <protocol.h>
#include <refreshkeysjob.h>
#include <receivekeysjob.h>

#include <QCoreApplication>
#include <QDebug>

#include <gpgme++/context.h>
#include <gpgme++/importresult.h>

#include <iostream>

using namespace GpgME;

std::ostream &operator<<(std::ostream &os, const QString &s)
{
    return os << s.toLocal8Bit().constData();
}

const char *displayName(Protocol protocol)
{
    switch (protocol) {
    case GpgME::OpenPGP:
        return "OpenPGP";
    case GpgME::CMS:
        return "S/MIME";
    default:
        return "Unknown protocol";
    }
}

struct KeyAndError {
    Key key;
    Error error;
};

KeyAndError getKey(const QString &keyId, Protocol protocol)
{
    KeyAndError result;

    auto ctx = Context::create(protocol);
    if (!ctx) {
        result.error = Error::fromCode(GPG_ERR_GENERAL);
        return result;
    }

    result.key = ctx->key(keyId.toLatin1().constData(), result.error);
    if (result.error.code() == GPG_ERR_EOF) {
        result.error = Error{};
    }
    return result;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " KEYID" << std::endl;
        return 1;
    }

    QCoreApplication app{argc, argv};
    const auto keyId = qApp->arguments().last();

    auto openPGPKey = getKey(keyId, GpgME::OpenPGP);
    auto smimeKey = getKey(keyId, GpgME::CMS);
    if ((!openPGPKey.key.isNull() && !smimeKey.key.isNull())
            || (openPGPKey.error.code() == GPG_ERR_AMBIGUOUS_NAME)
            || (smimeKey.error.code() == GPG_ERR_AMBIGUOUS_NAME)) {
        std::cerr << "Error: Multiple keys matching '" << keyId << "' found" << std::endl;
        return 1;
    } else if (openPGPKey.key.isNull() && smimeKey.key.isNull()) {
        std::cerr << "Error: No key matching '" << keyId << "' found" << std::endl;
        return 1;
    }
    if (openPGPKey.error) {
        std::cerr << "Warning: Error while getting OpenPGP key: " << openPGPKey.error.asString() << std::endl;
    }
    if (smimeKey.error) {
        std::cerr << "Warning: Error while getting S/MIME key: " << openPGPKey.error.asString() << std::endl;
    }
    auto key = openPGPKey.key.isNull() ? smimeKey.key : openPGPKey.key;
    std::cout << "Refreshing " << displayName(key.protocol()) << " key " << key.userID(0).id() << std::endl;

    if (key.protocol() == GpgME::OpenPGP) {
        auto job = QGpgME::openpgp()->receiveKeysJob();
        if (!job) {
            std::cerr << "Error: Could not create job to refresh OpenPGP key" << std::endl;
            return 1;
        }
        QObject::connect(job, &QGpgME::ReceiveKeysJob::result, &app, [](const GpgME::ImportResult &result, const QString &, const GpgME::Error &) {
            std::cout << "Result: " << result << std::endl;
            qApp->quit();
        });
        const auto err = job->start({QString::fromLatin1(key.primaryFingerprint())});
        if (err) {
            std::cerr << "Error: " << err.asString() << std::endl;
            return 1;
        }
    } else {
        auto job = QGpgME::smime()->refreshKeysJob();
        if (!job) {
            std::cerr << "Error: Could not create job to refresh S/MIME key" << std::endl;
            return 1;
        }
        QObject::connect(job, &QGpgME::RefreshKeysJob::result, &app, [](const GpgME::Error &err) {
            std::cout << "Result: " << err.asString() << std::endl;
            qApp->quit();
        });
        const auto err = job->start({key});
        if (err) {
            std::cerr << "Error: " << err.asString() << std::endl;
            return 1;
        }
    }

    return app.exec();
}

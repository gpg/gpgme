/*
    run-wkdrefreshjob.cpp

    This file is part of QGpgME's test suite.
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

#include <debug.h>
#include <protocol.h>
#include <wkdrefreshjob.h>

#include <QCommandLineParser>
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

struct CommandLineOptions {
    bool allUserIds;
    QString keyId;
};

CommandLineOptions parseCommandLine(const QStringList &arguments)
{
    CommandLineOptions options;

    QCommandLineParser parser;
    parser.setApplicationDescription("Test program for WKDRefreshJob");
    parser.addHelpOption();
    parser.addOptions({
        {"all-userids", "Query WKD for all user IDs."},
    });
    parser.addPositionalArgument("key ID", "Key to refresh");

    parser.process(arguments);

    const auto args = parser.positionalArguments();
    if (args.size() != 1) {
        parser.showHelp(1);
    }

    options.allUserIds = parser.isSet("all-userids");
    options.keyId = args[0];

    return options;
}

Key getOpenPGPKey(const QString &keyId, Error &err)
{
    Key key;

    auto ctx = Context::create(GpgME::OpenPGP);
    if (!ctx) {
        err = Error::fromCode(GPG_ERR_GENERAL);
        return key;
    }

    key = ctx->key(keyId.toLatin1().constData(), err);
    if (err.code() == GPG_ERR_EOF) {
        err = Error{};
    }
    return key;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};
    app.setApplicationName("run-wkdrefreshjob");

    const auto options = parseCommandLine(app.arguments());

    Error err;
    const auto key = getOpenPGPKey(options.keyId, err);
    if (err.code() == GPG_ERR_AMBIGUOUS_NAME) {
        std::cerr << "Error: Multiple OpenPGP keys matching '" << options.keyId << "' found" << std::endl;
        return 1;
    }
    if (key.isNull()) {
        std::cerr << "Error: No OpenPGP key matching '" << options.keyId << "' found" << std::endl;
        return 1;
    }
    if (err) {
        std::cerr << "Error while getting OpenPGP key: " << err << std::endl;
        return 1;
    }
    std::cout << "Refreshing OpenPGP key " << key.userID(0).id() << std::endl;

    auto job = QGpgME::openpgp()->wkdRefreshJob();
    if (!job) {
        std::cerr << "Error: Could not create job to refresh OpenPGP key" << std::endl;
        return 1;
    }
    QObject::connect(job, &QGpgME::WKDRefreshJob::result, &app, [](const GpgME::ImportResult &result, const QString &, const GpgME::Error &) {
        if (result.isNull()) {
            std::cout << "Empty result. Lookup via WKD failed or no user ID was originally retrieved via WKD." << std::endl;
        } else {
            std::cout << "Result: " << result << std::endl;
        }
        qApp->quit();
    });
    if (options.allUserIds) {
        err = job->start(key.userIDs());
    } else {
        err = job->start({key});
    }
    if (err) {
        std::cerr << "Error: " << err << std::endl;
        return 1;
    }

    return app.exec();
}

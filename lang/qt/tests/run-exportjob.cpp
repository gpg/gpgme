/*
    run-exportjob.cpp

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <exportjob.h>
#include <protocol.h>

#include <gpgme++/context.h>

#include <QCoreApplication>

#include <iostream>

using namespace GpgME;
using std::cout;
using std::cerr;

static void showUsageAndExitWithCode(int exitCode)
{
    cerr << "Usage: run-exportjob [OPTION]... [PATTERN]...\n"
         "Options:\n"
         "  --secret         export secret keys instead of public keys\n"
         "  --secret-subkey  export secret subkeys instead of public keys\n";

    exit(exitCode);
}

static QGpgME::ExportJob *createExportJob(unsigned int mode)
{
    if (mode & Context::ExportSecretSubkey) {
        return QGpgME::openpgp()->secretSubkeyExportJob(/*armor=*/true);
    } else if (mode & Context::ExportSecret) {
        return QGpgME::openpgp()->secretKeyExportJob(/*armor=*/true);
    }
    return QGpgME::openpgp()->publicKeyExportJob(/*armor=*/true);
}

int main(int argc, char *argv[])
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};

    unsigned int exportMode = 0;

    auto arguments = app.arguments();
    if (!arguments.isEmpty()) {
        arguments.pop_front(); // remove program name
    }
    while (!arguments.isEmpty()) {
        const auto &arg = arguments.front();
        if (!arg.startsWith(QLatin1String{"--"})) {
            break;
        }
        if (arg == QLatin1String{"--"}) {
            arguments.pop_front();
            break;
        }
        if (arg == QLatin1String{"--help"}) {
            showUsageAndExitWithCode(0);
        } else if (arg == QLatin1String{"--secret"}) {
            exportMode = Context::ExportSecret;
            arguments.pop_front();
        } else if (arg == QLatin1String{"--secret-subkey"}) {
            exportMode = Context::ExportSecretSubkey;
            arguments.pop_front();
        } else {
            cerr << "Error: Invalid option " << arg.toStdString() << std::endl;
            showUsageAndExitWithCode(1);
        }
    }

    auto job = createExportJob(exportMode);
    QObject::connect(job, &QGpgME::ExportJob::result,
                     &app, [&app] (const GpgME::Error &err, const QByteArray &keyData, const QString &, const GpgME::Error &) {
                         if (err) {
                             cerr << "The ChangeExpiryJob failed with" << err.asString() << ".";
                             app.exit(1);
                             return;
                         }
                         cout << "Begin Result:\n" << keyData.toStdString() << "End Result:\n";
                         app.exit();
                     });
    job->start(arguments);

    return app.exec();
}

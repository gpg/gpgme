/*
    run-decryptverifyarchivejob.cpp

    This file is part of QGpgME's test suite.
    Copyright (c) 2023 by g10 Code GmbH
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

#include <decryptverifyarchivejob.h>
#include <protocol.h>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>

#include <gpgme++/context.h>
#include <gpgme++/decryptionresult.h>
#include <gpgme++/verificationresult.h>

#include <iostream>

using namespace GpgME;

std::ostream &operator<<(std::ostream &os, const QString &s)
{
    return os << s.toLocal8Bit().constData();
}

struct CommandLineOptions {
    QString outputDirectory;
    QString archiveName;
};

CommandLineOptions parseCommandLine(const QStringList &arguments)
{
    CommandLineOptions options;

    QCommandLineParser parser;
    parser.setApplicationDescription("Test program for DecryptVerifyArchiveJob");
    parser.addHelpOption();
    parser.addOptions({
        {{"C", "directory"}, "Extract the files into the directory DIRECTORY.", "DIRECTORY"},
    });
    parser.addPositionalArgument("archive", "The archive to decrypt and extract");

    parser.process(arguments);

    const auto args = parser.positionalArguments();
    if (args.size() != 1) {
        parser.showHelp(1);
    }

    options.outputDirectory = parser.value("directory");
    options.archiveName = args.first();

    return options;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};
    app.setApplicationName("run-decryptverifyarchivejob");

    const auto options = parseCommandLine(app.arguments());

    if (!QGpgME::DecryptVerifyArchiveJob::isSupported()) {
        std::cerr << "Error: Decrypting and extracting archives is not supported by your version of gpg." << std::endl;
        return 1;
    }

    auto job = QGpgME::openpgp()->decryptVerifyArchiveJob();
    if (!job) {
        std::cerr << "Error: Could not create job" << std::endl;
        return 1;
    }
    job->setInputFile(options.archiveName);
    job->setOutputDirectory(options.outputDirectory);
    QObject::connect(job, &QGpgME::DecryptVerifyArchiveJob::result, &app, [](const GpgME::DecryptionResult &decryptionResult, const GpgME::VerificationResult &verificationResult, const QString &auditLog, const GpgME::Error &) {
        std::cerr << "Diagnostics: " << auditLog << std::endl;
        std::cerr << "Decryption Result: " << decryptionResult << std::endl;
        std::cerr << "Verification Result: " << verificationResult << std::endl;
        qApp->quit();
    });

    const auto err = job->startIt();
    if (err) {
        std::cerr << "Error: Starting the job failed: " << err.asString() << std::endl;
        return 1;
    }

    return app.exec();
}

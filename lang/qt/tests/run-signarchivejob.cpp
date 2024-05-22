/*
    run-signarchivejob.cpp

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

#include <protocol.h>
#include <signarchivejob.h>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>

#include <gpgme++/context.h>
#include <gpgme++/signingresult.h>

#include <iostream>

using namespace GpgME;

std::ostream &operator<<(std::ostream &os, const QString &s)
{
    return os << s.toLocal8Bit().constData();
}

struct CommandLineOptions {
    bool armor;
    QString archiveName;
    QString baseDirectory;
    std::chrono::seconds cancelTimeout{0};
    std::vector<QString> filesAndDirectories;
};

CommandLineOptions parseCommandLine(const QStringList &arguments)
{
    CommandLineOptions options;

    QCommandLineParser parser;
    parser.setApplicationDescription("Test program for SignArchiveJob");
    parser.addHelpOption();
    parser.addOptions({
        {{"o", "output"}, "Write output to FILE.", "FILE"},
        {{"a", "armor"}, "Create ASCII armored output."},
        {{"C", "directory"}, "Change to DIRECTORY before creating the archive.", "DIRECTORY"},
        {"cancel-after", "Cancel the running job after SECONDS seconds.", "SECONDS"},
    });
    parser.addPositionalArgument("files", "Files and directories to add to the archive", "[files] [directories]");

    parser.process(arguments);

    const auto args = parser.positionalArguments();
    if (args.empty()) {
        parser.showHelp(1);
    }

    options.armor = parser.isSet("armor");
    options.archiveName = parser.value("output");
    options.baseDirectory = parser.value("directory");
    if (parser.isSet("cancel-after")) {
        bool ok;
        options.cancelTimeout = std::chrono::seconds{parser.value("cancel-after").toInt(&ok)};
        if (!ok) {
            options.cancelTimeout = std::chrono::seconds{-1};
        }
    }
    std::copy(args.begin(), args.end(), std::back_inserter(options.filesAndDirectories));

    return options;
}

QString checkOutputFilePath(const QString &fileName, const QString &baseDirectory)
{
    const QFileInfo fi{QDir{baseDirectory}, fileName};
    if (fi.exists()) {
        qCritical() << "File" << fi.filePath() << "exists. Bailing out.";
        return {};
    }
    return fileName;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};
    app.setApplicationName("run-signarchivejob");

    const auto options = parseCommandLine(app.arguments());
    if (options.cancelTimeout.count() < 0) {
        std::cerr << "Ignoring invalid timeout for cancel." << std::endl;
    }

    if (!QGpgME::SignArchiveJob::isSupported()) {
        std::cerr << "Error: Signing archives is not supported by your version of gpg." << std::endl;
        return 1;
    }

    std::shared_ptr<QFile> output;
    QString outputFilePath;
    if (options.archiveName.isEmpty() || options.archiveName == QLatin1String{"-"}) {
        output.reset(new QFile);
        output->open(stdout, QIODevice::WriteOnly);
    } else {
        outputFilePath = checkOutputFilePath(options.archiveName, options.baseDirectory);
        if (outputFilePath.isEmpty()) {
            return 1;
        }
    }

    auto job = QGpgME::openpgp()->signArchiveJob(options.armor);
    if (!job) {
        std::cerr << "Error: Could not create job" << std::endl;
        return 1;
    }
    job->setBaseDirectory(options.baseDirectory);
    QObject::connect(job, &QGpgME::SignArchiveJob::result, &app, [](const GpgME::SigningResult &result, const QString &auditLog, const GpgME::Error &) {
        std::cerr << "Diagnostics: " << auditLog << std::endl;
        std::cerr << "Result: " << result << std::endl;
        qApp->quit();
    });
    if (options.cancelTimeout.count() > 0) {
        QTimer::singleShot(options.cancelTimeout, job, [job]() {
            std::cerr << "Canceling job" << std::endl;
            job->slotCancel();
        });
    }

    GpgME::Error err;
    if (output) {
        err = job->start({}, options.filesAndDirectories, output);
    } else {
        job->setInputPaths(options.filesAndDirectories);
        job->setOutputFile(outputFilePath);
        err = job->startIt();
    }
    if (err) {
        std::cerr << "Error: Starting the job failed: " << err.asString() << std::endl;
        return 1;
    }

    return app.exec();
}

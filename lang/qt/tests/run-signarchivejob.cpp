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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <protocol.h>
#include <signarchivejob.h>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>
#include <QFile>

#include <context.h>
#include <signingresult.h>

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
    std::copy(args.begin(), args.end(), std::back_inserter(options.filesAndDirectories));

    return options;
}

std::shared_ptr<QIODevice> createOutput(const QString &fileName)
{
    std::shared_ptr<QFile> output;

    if (fileName.isEmpty()) {
        output.reset(new QFile);
        output->open(stdout, QIODevice::WriteOnly);
    } else {
        if (QFile::exists(fileName)) {
            qCritical() << "File" << fileName << "exists. Bailing out.";
        } else {
            output.reset(new QFile{fileName});
            output->open(QIODevice::WriteOnly);
        }
    }

    return output;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};
    app.setApplicationName("run-signarchivejob");

    const auto options = parseCommandLine(app.arguments());

    if (!QGpgME::SignArchiveJob::isSupported()) {
        std::cerr << "Error: Signing archives is not supported by your version of gpg." << std::endl;
        return 1;
    }

    auto output = createOutput(options.archiveName);
    if (!output) {
        return 1;
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

    const auto err = job->start({}, options.filesAndDirectories, output);
    if (err) {
        std::cerr << "Error: Starting the job failed: " << err.asString() << std::endl;
        return 1;
    }

    return app.exec();
}

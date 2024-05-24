/*
    run-signjob.cpp

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
#include <signjob.h>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QDebug>
#include <QFile>
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
    GpgME::SignatureMode signingFlags = GpgME::NormalSignatureMode;
    bool armor = false;
    bool appendSignature = false;
    QString inputFile;
    QString outputFile;
    std::chrono::seconds cancelTimeout{0};
};

CommandLineOptions parseCommandLine(const QStringList &arguments)
{
    CommandLineOptions options;

    QCommandLineParser parser;
    parser.setApplicationDescription("Test program for SignJob");
    parser.addHelpOption();
    parser.addOptions({
        {{"o", "output"}, "Write output to FILE.", "FILE"},
        {{"a", "armor"}, "Create ASCII armored output."},
        {{"b", "detach-sign"}, "Create a detached signature."},
        {"append", "Append new (detached) signature to existing file."},
        {"cancel-after", "Cancel the running job after SECONDS seconds.", "SECONDS"},
    });
    parser.addPositionalArgument("file", "File to sign", "FILE");

    parser.process(arguments);

    const auto args = parser.positionalArguments();
    if (args.size() != 1) {
        parser.showHelp(1);
    }

    options.armor = parser.isSet("armor");
    if (parser.isSet("detach-sign")) {
        options.signingFlags = GpgME::Detached;
        options.appendSignature = parser.isSet("append");
    }
    options.inputFile = args.front();
    options.outputFile = parser.value("output");
    if (parser.isSet("cancel-after")) {
        bool ok;
        options.cancelTimeout = std::chrono::seconds{parser.value("cancel-after").toInt(&ok)};
        if (!ok) {
            options.cancelTimeout = std::chrono::seconds{-1};
        }
    }

    return options;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    QCoreApplication app{argc, argv};
    app.setApplicationName("run-signjob");

    const auto options = parseCommandLine(app.arguments());
    if (options.cancelTimeout.count() < 0) {
        std::cerr << "Ignoring invalid timeout for cancel." << std::endl;
    }

    std::shared_ptr<QFile> output;
    if (options.outputFile.isEmpty() || options.outputFile == QLatin1String{"-"}) {
        output.reset(new QFile);
        output->open(stdout, QIODevice::WriteOnly);
    } else {
        if (QFile::exists(options.outputFile) && !options.appendSignature) {
            qCritical() << "File" << options.outputFile << "exists. Bailing out.";
            return 1;
        }
    }

    auto job = QGpgME::openpgp()->signJob(options.armor);
    if (!job) {
        std::cerr << "Error: Could not create job" << std::endl;
        return 1;
    }
    QObject::connect(job, &QGpgME::SignJob::result, &app, [](const GpgME::SigningResult &result, const QByteArray &, const QString &auditLog, const GpgME::Error &) {
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

    std::shared_ptr<QFile> input;
    GpgME::Error err;
    if (output) {
        input.reset(new QFile{options.inputFile});
        input->open(QIODevice::ReadOnly);
        job->start({}, input, output, GpgME::NormalSignatureMode);
    } else {
        job->setInputFile(options.inputFile);
        job->setOutputFile(options.outputFile);
        job->setSigningFlags(options.signingFlags);
        job->setAppendSignature(options.appendSignature);
        err = job->startIt();
    }
    if (err) {
        std::cerr << "Error: Starting the job failed: " << err.asString() << std::endl;
        return 1;
    }

    return app.exec();
}

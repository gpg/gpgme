/*
    run-importjob.cpp

    This file is part of QGpgME's test suite.
    Copyright (c) 2021 by g10 Code GmbH
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

#include <debug.h>
#include <importjob.h>
#include <importresult.h>
#include <protocol.h>

#include <QFile>
#include <QFileInfo>

#include <QDebug>

#include <set>

GpgME::Protocol guessProtocol(const QString &filename)
{
    static const std::set<QString> cmsExtensions = {"cer", "crt", "der", "p12", "p7c", "pem", "pfx"};
    static const std::set<QString> pgpExtensions = {"asc", "gpg", "pgp"};

    const auto extension = QFileInfo{filename}.suffix();
    if (cmsExtensions.find(extension) != cmsExtensions.end()) {
        return GpgME::CMS;
    } else if (pgpExtensions.find(extension) != pgpExtensions.end()) {
        return GpgME::OpenPGP;
    }
    qDebug() << "Unknown file name extension" << extension;
    return GpgME::UnknownProtocol;
}

int main(int argc, char **argv)
{
    GpgME::initializeLibrary();

    if (argc != 2) {
        qInfo().noquote() << "Usage:" << argv[0] << "<certificate file>";
        return 1;
    }
    const auto filename = QString::fromLocal8Bit(argv[1]);

    QFile f{filename};
    if (!f.exists()) {
        qWarning() << "Error: File not found" << filename;
        return 1;
    }
    const auto protocol = guessProtocol(filename);
    if (protocol == GpgME::UnknownProtocol) {
        qWarning() << "Error: Unknown file type";
        return 1;
    }
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "Error: Failed to open file" << filename << "for reading.";
        return 1;
    }

    const auto keyData = f.readAll();
    auto job = (protocol == GpgME::CMS ? QGpgME::smime() : QGpgME::openpgp())->importJob();
    const auto result = job->exec(keyData);
    qDebug() << "Result error:" << result.error().asString();
    for (const auto &line : QString::fromStdString(QGpgME::toLogString(result)).split('\n')) {
        qDebug().noquote() << line;
    }
    return 0;
}

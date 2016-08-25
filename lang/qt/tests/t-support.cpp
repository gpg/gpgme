/* t-support.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2016 Intevation GmbH

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

#include "t-support.h"

#include <QTest>

void QGpgMETest::initTestCase()
{
    const QString gpgHome = qgetenv("GNUPGHOME");
    QVERIFY2(!gpgHome.isEmpty(), "GNUPGHOME environment variable is not set.");
}

void QGpgMETest::cleanupTestCase()
{
    QCoreApplication::sendPostedEvents();
    killAgent();
}

bool QGpgMETest::copyKeyrings(const QString &src, const QString &dest)
{
    bool is21dir = QFileInfo(src + QDir::separator() + QStringLiteral("pubring.kbx")).exists();
    const QString name = is21dir ? QStringLiteral("pubring.kbx") :
                                  QStringLiteral("pubring.gpg");
    if (!QFile::copy(src + name, dest + QDir::separator() + name)) {
        return false;
    }
    if (!is21dir) {
        return (QFile::copy(src + QDir::separator() + QStringLiteral("secring.gpg"),
                 dest + QDir::separator() + QStringLiteral("secring.gpg")));
    }
    QDir dir (src + QDir::separator() + QStringLiteral("private-keys-v1.d"));
    QDir target(dest);
    if (!target.mkdir("private-keys-v1.d")) {
        return false;
    }
    foreach (QString f, dir.entryList(QDir::Files)) {
        if (!QFile::copy(src + QDir::separator() + f, dest + QDir::separator() + f)) {
            return false;
        }
    }
    return true;
}

void killAgent(const QString& dir)
{
    QProcess proc;
    proc.setProgram(QStringLiteral("gpg-connect-agent"));
    QStringList arguments;
    arguments << "-S " << dir + "/S.gpg-agent";
    proc.start();
    proc.waitForStarted();
    proc.write("KILLAGENT\n");
    proc.write("BYE\n");
    proc.closeWriteChannel();
    proc.waitForFinished();
}


#include "t-support.hmoc"

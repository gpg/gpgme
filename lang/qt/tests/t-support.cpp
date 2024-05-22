/* t-support.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH

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

#include "importjob.h"
#include "job.h"
#include "protocol.h"

#include <QTest>

#include <QProcess>
#include <QCoreApplication>
#include <QObject>
#include <QDir>
#include <QSignalSpy>

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include <gpgme++/importresult.h>

using namespace GpgME;
using namespace QGpgME;

void QGpgMETest::initTestCase()
{
    GpgME::initializeLibrary();
    const QString gpgHome = qgetenv("GNUPGHOME");
    QVERIFY2(!gpgHome.isEmpty(), "GNUPGHOME environment variable is not set.");
}

void QGpgMETest::cleanupTestCase()
{
    QCoreApplication::sendPostedEvents();
    killAgent();
}

// static
bool QGpgMETest::doOnlineTests()
{
    return !qgetenv("DO_ONLINE_TESTS").isEmpty();
}

bool QGpgMETest::copyKeyrings(const QString &src, const QString &dest)
{
    bool is21dir = QFileInfo(src + QDir::separator() + QStringLiteral("pubring.kbx")).exists();
    const QString name = is21dir ? QStringLiteral("pubring.kbx") :
                                  QStringLiteral("pubring.gpg");
    if (!QFile::copy(src + QDir::separator() + name, dest + QDir::separator() + name)) {
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
        if (!QFile::copy(dir.path() + QDir::separator() + f,
                         dest + QDir::separator() +
                         QStringLiteral("private-keys-v1.d") + QDir::separator() + f)) {
            return false;
        }
    }
    return true;
}

bool QGpgMETest::importSecretKeys(const char *keyData, int expectedKeys)
{
    auto job = std::unique_ptr<ImportJob>{openpgp()->importJob()};
    VERIFY_OR_FALSE(job);
    hookUpPassphraseProvider(job.get());

    ImportResult result;
    connect(job.get(), &ImportJob::result,
            this, [this, &result](const ImportResult &result_) {
                result = result_;
                Q_EMIT asyncDone();
            });
    VERIFY_OR_FALSE(!job->start(keyData));
    job.release(); // after the job has been started it's on its own

    QSignalSpy spy (this, SIGNAL(asyncDone()));
    VERIFY_OR_FALSE(spy.wait(QSIGNALSPY_TIMEOUT));
    VERIFY_OR_FALSE(!result.error());
    VERIFY_OR_FALSE(!result.imports().empty());
    COMPARE_OR_FALSE(result.numSecretKeysImported(), expectedKeys);

    return true;
}

void QGpgMETest::hookUpPassphraseProvider(GpgME::Context *context)
{
    context->setPassphraseProvider(&mPassphraseProvider);
    context->setPinentryMode(Context::PinentryLoopback);
}

void QGpgMETest::hookUpPassphraseProvider(QGpgME::Job *job)
{
    hookUpPassphraseProvider(Job::context(job));
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

bool loopbackSupported()
{
    /* With GnuPG 2.0.x (at least 2.0.26 by default on jessie)
     * the passphrase_cb does not work. So the test popped up
     * a pinentry. So tests requiring decryption don't work. */
    static auto version = GpgME::engineInfo(GpgME::GpgEngine).engineVersion();
    if (version < "2.0.0") {
        /* With 1.4 it just works */
        return true;
    }
    if (version < "2.1.0") {
        /* With 2.1 it works with loopback mode */
        return false;
    }
    return true;
}

#include "t-support.hmoc"

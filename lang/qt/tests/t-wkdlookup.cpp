/* t-wkdlookup.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2021 g10 Code GmbH
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

#include "t-support.h"

#include <gpgme++/data.h>
#include <gpgme++/engineinfo.h>
#include "protocol.h"
#include "wkdlookupjob.h"
#include "wkdlookupresult.h"

#include <QDebug>
#include <QSignalSpy>
#include <QTest>

#include <algorithm>

using namespace QGpgME;
using namespace GpgME;

static const char *requiredVersion = "2.1.12";

namespace
{
bool keyHasUserIDWithMatchingEmailAddress(const Key &key, const QString &expectedEmailAddress)
{
    const auto email = expectedEmailAddress.toLower();
    const auto userIds = key.userIDs();
    return std::any_of(
        std::begin(userIds), std::end(userIds),
        [email](const UserID &uid) {
            return email == QString::fromUtf8(uid.email()).toLower();
        });
}
}

class WKDLookupTest : public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:

    void testWKDLookupAsync()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < requiredVersion) {
            QSKIP("dirmngr does not yet support WKD lookup");
        }
        if (!doOnlineTests()) {
            QSKIP("Set DO_ONLINE_TESTS environment variable to run this test.");
        }
        const QString email = QLatin1String{"wk@gnupg.org"};

        WKDLookupResult result;
        auto *job = openpgp()->wkdLookupJob();
        connect(job, &WKDLookupJob::result, job, [this, &result](const WKDLookupResult &result_, const QString &, const Error &)
        {
            result = result_;
            Q_EMIT asyncDone();
        });
        job->start(email);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        QVERIFY(result.error().code() == GPG_ERR_NO_ERROR);
        QCOMPARE(result.pattern(), "wk@gnupg.org");
        QCOMPARE(result.source(), "https://openpgpkey.gnupg.org");
        const auto keys = result.keyData().toKeys(GpgME::OpenPGP);
        QVERIFY(keys.size() == 1);
        QVERIFY(keyHasUserIDWithMatchingEmailAddress(keys.front(), email));
    }

    void testWKDLookupSync()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < requiredVersion) {
            QSKIP("dirmngr does not yet support WKD lookup");
        }
        if (!doOnlineTests()) {
            QSKIP("Set DO_ONLINE_TESTS environment variable to run this test.");
        }
        const QString email = QLatin1String{"wk@gnupg.org"};

        auto *job = openpgp()->wkdLookupJob();
        const auto result = job->exec(email);

        QVERIFY(result.error().code() == GPG_ERR_NO_ERROR);
        QCOMPARE(result.pattern(), "wk@gnupg.org");
        QCOMPARE(result.source(), "https://openpgpkey.gnupg.org");
        const auto keys = result.keyData().toKeys(GpgME::OpenPGP);
        QVERIFY(keys.size() == 1);
        QVERIFY(keyHasUserIDWithMatchingEmailAddress(keys.front(), email));
    }

    void testLookupWithNoResultAsync()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < requiredVersion) {
            QSKIP("dirmngr does not yet support WKD lookup");
        }
        if (!doOnlineTests()) {
            QSKIP("Set DO_ONLINE_TESTS environment variable to run this test.");
        }
        const QString email = QLatin1String{"alfa@example.net"};

        WKDLookupResult result;
        auto *job = openpgp()->wkdLookupJob();
        connect(job, &WKDLookupJob::result, job, [this, &result](const WKDLookupResult &result_, const QString &, const Error &)
        {
            result = result_;
            Q_EMIT asyncDone();
        });
        job->start(email);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        QVERIFY(result.error().code() == GPG_ERR_NO_ERROR);
        QCOMPARE(result.pattern(), "alfa@example.net");
        QCOMPARE(result.source(), "");
        QVERIFY(result.keyData().isNull());
    }
};

QTEST_MAIN(WKDLookupTest)

#include "t-wkdlookup.moc"

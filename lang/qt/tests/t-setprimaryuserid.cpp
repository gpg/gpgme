/* t-setprimaryuserid.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2022 g10 Code GmbH
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

#include <keylistjob.h>
#include <protocol.h>

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include <gpgme++/keylistresult.h>

using namespace QGpgME;
using namespace GpgME;

class TestSetPrimaryUserID: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void testSetPrimaryUserID()
    {
        Key key;
        {
            std::unique_ptr<KeyListJob> job{openpgp()->keyListJob()};
            std::vector<GpgME::Key> keys;
            GpgME::KeyListResult result = job->exec({QStringLiteral("alfa@example.net")}, true, keys);
            QVERIFY(!result.error());
            QVERIFY(keys.size() == 1);
            key = keys.front();
        }

        QCOMPARE(key.numUserIDs(), 3u);
        const std::string oldPrimaryUserId = key.userID(0).id();
        const std::string newPrimaryUserId = key.userID(1).id();
        const std::string newPrimaryUserIdHash = key.userID(1).uidhash();

        {
            std::unique_ptr<Context> ctx{Context::createForProtocol(key.protocol())};
            QVERIFY(ctx);
            hookUpPassphraseProvider(ctx.get());

            if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() >= "2.3.8") {
                QVERIFY(!ctx->setPrimaryUid(key, newPrimaryUserIdHash.c_str()));
            } else {
                QVERIFY(!ctx->setPrimaryUid(key, newPrimaryUserId.c_str()));
            }
        }
        key.update();

        QCOMPARE(key.userID(0).id(), newPrimaryUserId);

        {
            std::unique_ptr<Context> ctx{Context::createForProtocol(key.protocol())};
            QVERIFY(ctx);
            hookUpPassphraseProvider(ctx.get());

            QVERIFY(!ctx->setPrimaryUid(key, oldPrimaryUserId.c_str()));
        }
        key.update();

        QCOMPARE(key.userID(0).id(), oldPrimaryUserId);
    }

    void testErrorHandling_noSecretKey()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.3.8") {
            QSKIP("gpg < 2.3.8 does not report status error");
        }
        Key key;
        {
            std::unique_ptr<KeyListJob> job{openpgp()->keyListJob()};
            std::vector<GpgME::Key> keys;
            GpgME::KeyListResult result = job->exec({QStringLiteral("bravo@example.net")}, false, keys);
            QVERIFY(!result.error());
            QVERIFY(keys.size() == 1);
            key = keys.front();
        }

        QCOMPARE(key.numUserIDs(), 2u);
        const std::string newPrimaryUserId = key.userID(1).id();

        {
            std::unique_ptr<Context> ctx{Context::createForProtocol(key.protocol())};
            QVERIFY(ctx);
            auto err = ctx->setPrimaryUid(key, newPrimaryUserId.c_str());
            QCOMPARE(err.code(), static_cast<int>(GPG_ERR_NO_SECKEY));
        }
    }

    void testErrorHandling_noUserID()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.3.8") {
            QSKIP("gpg < 2.3.8 does not report status error");
        }
        Key key;
        {
            std::unique_ptr<KeyListJob> job{openpgp()->keyListJob()};
            std::vector<GpgME::Key> keys;
            GpgME::KeyListResult result = job->exec({QStringLiteral("alfa@example.net")}, true, keys);
            QVERIFY(!result.error());
            QVERIFY(keys.size() == 1);
            key = keys.front();
        }
        {
            std::unique_ptr<Context> ctx{Context::createForProtocol(key.protocol())};
            QVERIFY(ctx);
            auto err = ctx->setPrimaryUid(key, "bravo");
            QCOMPARE(err.code(), static_cast<int>(GPG_ERR_NO_USER_ID));
        }
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        QVERIFY(copyKeyrings(gpgHome, mDir.path()));
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        QFile conf(mDir.path() + QStringLiteral("/gpg.conf"));
        QVERIFY(conf.open(QIODevice::WriteOnly));
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() >= "2.2.18") {
            conf.write("allow-weak-key-signatures\n");
        }
        conf.close();
    }

private:
    QTemporaryDir mDir;
};

QTEST_MAIN(TestSetPrimaryUserID)

#include "t-setprimaryuserid.moc"

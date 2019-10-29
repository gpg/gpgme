/* t-various.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2017 by Bundesamt für Sicherheit in der Informationstechnik
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "keylistjob.h"
#include "protocol.h"
#include "keylistresult.h"
#include "context.h"
#include "engineinfo.h"
#include "dn.h"
#include "data.h"
#include "dataprovider.h"
#include "signkeyjob.h"

#include "t-support.h"

using namespace QGpgME;
using namespace GpgME;

static const char aKey[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
"\n"
"mDMEWG+w/hYJKwYBBAHaRw8BAQdAiq1oStvDYg8ZfFs5DgisYJo8dJxD+C/AA21O\n"
"K/aif0O0GXRvZnVfY29uZmxpY3RAZXhhbXBsZS5jb22IlgQTFggAPhYhBHoJBLaV\n"
"DamYAgoa1L5BwMOl/x88BQJYb7D+AhsDBQkDwmcABQsJCAcCBhUICQoLAgQWAgMB\n"
"Ah4BAheAAAoJEL5BwMOl/x88GvwA/0SxkbLyAcshGm2PRrPsFQsSVAfwaSYFVmS2\n"
"cMVIw1PfAQDclRH1Z4MpufK07ju4qI33o4s0UFpVRBuSxt7A4P2ZD7g4BFhvsP4S\n"
"CisGAQQBl1UBBQEBB0AmVrgaDNJ7K2BSalsRo2EkRJjHGqnp5bBB0tapnF81CQMB\n"
"CAeIeAQYFggAIBYhBHoJBLaVDamYAgoa1L5BwMOl/x88BQJYb7D+AhsMAAoJEL5B\n"
"wMOl/x88OR0BAMq4/vmJUORRTmzjHcv/DDrQB030DSq666rlckGIKTShAPoDXM9N\n"
"0gZK+YzvrinSKZXHmn0aSwmC1/hyPybJPEljBw==\n"
"=p2Oj\n"
"-----END PGP PUBLIC KEY BLOCK-----\n";

class TestVarious: public QGpgMETest
{
    Q_OBJECT

Q_SIGNALS:
    void asyncDone();

private Q_SLOTS:
    void testDN()
    {
        DN dn(QStringLiteral("CN=Before\\0DAfter,OU=Test,DC=North America,DC=Fabrikam,DC=COM"));
        QVERIFY(dn.dn() == QStringLiteral("CN=Before\rAfter,OU=Test,DC=North America,DC=Fabrikam,DC=COM"));
        QStringList attrOrder;
        attrOrder << QStringLiteral("DC") << QStringLiteral("OU") << QStringLiteral("CN");
        dn.setAttributeOrder(attrOrder);
        QVERIFY(dn.prettyDN() == QStringLiteral("DC=North America,DC=Fabrikam,DC=COM,OU=Test,CN=Before\rAfter"));
    }

    void testKeyFromFile()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.14") {
            return;
        }
        QGpgME::QByteArrayDataProvider dp(aKey);
        Data data(&dp);
        const auto keys = data.toKeys();
        QVERIFY(keys.size() == 1);
        const auto key = keys[0];
        QVERIFY(!key.isNull());
        QVERIFY(key.primaryFingerprint() == QStringLiteral("7A0904B6950DA998020A1AD4BE41C0C3A5FF1F3C"));
    }

    void testDataRewind()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.14") {
            return;
        }
        QGpgME::QByteArrayDataProvider dp(aKey);
        Data data(&dp);
        char buf[20];
        data.read(buf, 20);

        auto keys = data.toKeys();
        QVERIFY(keys.size() == 0);

        data.rewind();

        keys = data.toKeys();
        QVERIFY(keys.size() == 1);
    }

    void testQuickUid()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.13") {
            return;
        }
        KeyListJob *job = openpgp()->keyListJob(false, true, true);
        std::vector<GpgME::Key> keys;
        GpgME::KeyListResult result = job->exec(QStringList() << QStringLiteral("alfa@example.net"),
                                                false, keys);
        delete job;
        QVERIFY (!result.error());
        QVERIFY (keys.size() == 1);
        Key key = keys.front();

        QVERIFY (key.numUserIDs() == 3);
        const char uid[] = "Foo Bar (with comment) <foo@bar.baz>";

        auto ctx = Context::createForProtocol(key.protocol());
        QVERIFY (ctx);
        TestPassphraseProvider provider;
        ctx->setPassphraseProvider(&provider);
        ctx->setPinentryMode(Context::PinentryLoopback);

        QVERIFY(!ctx->addUid(key, uid));
        delete ctx;
        key.update();

        QVERIFY (key.numUserIDs() == 4);
        bool id_found = false;;
        for (const auto &u: key.userIDs()) {
            if (!strcmp (u.id(), uid)) {
                QVERIFY (!u.isRevoked());
                id_found = true;
                break;
            }
        }
        QVERIFY (id_found);

        ctx = Context::createForProtocol(key.protocol());
        QVERIFY (!ctx->revUid(key, uid));
        delete ctx;
        key.update();

        bool id_revoked = false;;
        for (const auto &u: key.userIDs()) {
            if (!strcmp (u.id(), uid)) {
                id_revoked = true;
                break;
            }
        }
        QVERIFY(id_revoked);
    }

    void testRemark()
    {
        // Get the signing key (alfa)
        auto ctx = Context::create(OpenPGP);
        QVERIFY (ctx);
        Error err;
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY (!seckey.isNull());
        QVERIFY (!err);

        // Get the target key (mallory / mike)
        auto target = ctx->key("2686AA191A278013992C72EBBE794852BE5CF886", err, false);
        QVERIFY (!target.isNull());
        QVERIFY (!err);
        QVERIFY (target.numUserIDs());

        // Create the job
        auto job = openpgp()->signKeyJob();
        QVERIFY (job);

        // Hack in the passphrase provider
        auto jobCtx = Job::context(job);
        TestPassphraseProvider provider;
        jobCtx->setPassphraseProvider(&provider);
        jobCtx->setPinentryMode(Context::PinentryLoopback);

        // Setup the job
        job->setExportable(false);
        std::vector<unsigned int> uids;
        uids.push_back(0);
        job->setUserIDsToSign(uids);
        job->setSigningKey(seckey);
        job->setRemark(QStringLiteral("Mallory is evil 😠"));

        connect(job, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                        const QString,
                                                        const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job->start(target);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the remark should have been added.
        target.update();
        const char *remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        Q_ASSERT(remark);
        QCOMPARE(QString::fromUtf8(remark), QStringLiteral("Mallory is evil 😠"));

        // Try to replace it without dupeOK
        auto job2 = openpgp()->signKeyJob();
        QVERIFY (job2);

        // Hack in the passphrase provider
        auto jobCtx2 = Job::context(job2);
        jobCtx2->setPassphraseProvider(&provider);
        jobCtx2->setPinentryMode(Context::PinentryLoopback);

        // Setup the job
        job2->setExportable(false);
        job2->setUserIDsToSign(uids);
        job2->setSigningKey(seckey);
        job2->setRemark(QStringLiteral("Mallory is nice"));

        connect(job2, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(err2);
        });

        job2->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // Now replace the remark
        auto job3 = openpgp()->signKeyJob();
        QVERIFY (job3);

        // Hack in the passphrase provider
        auto jobCtx3 = Job::context(job3);
        jobCtx3->setPassphraseProvider(&provider);
        jobCtx3->setPinentryMode(Context::PinentryLoopback);

        // Setup the job
        job3->setExportable(false);
        job3->setUserIDsToSign(uids);
        job3->setSigningKey(seckey);
        job3->setDupeOk(true);
        job3->setRemark(QStringLiteral("Mallory is nice"));

        connect(job3, &SignKeyJob::result, this, [this] (const GpgME::Error &err2,
                                                         const QString,
                                                         const GpgME::Error) {
            Q_EMIT asyncDone();
            QVERIFY(!err2);
        });

        job3->start(target);
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        target.update();
        remark = target.userID(0).remark(seckey, err);
        QVERIFY(!err);
        Q_ASSERT(remark);
        Q_ASSERT(QString::fromUtf8(remark) == QStringLiteral("Mallory is nice"));
    }

    void testVersion()
    {
        QVERIFY(EngineInfo::Version("2.1.0") < EngineInfo::Version("2.1.1"));
        QVERIFY(EngineInfo::Version("2.1.10") < EngineInfo::Version("2.1.11"));
        QVERIFY(EngineInfo::Version("2.2.0") > EngineInfo::Version("2.1.19"));
        QVERIFY(EngineInfo::Version("1.0.0") < EngineInfo::Version("2.0.0"));
        QVERIFY(EngineInfo::Version("0.1.0") < EngineInfo::Version("1.0.0"));
        QVERIFY(!(EngineInfo::Version("2.0.0") < EngineInfo::Version("2.0.0")));
        QVERIFY(EngineInfo::Version("3.0.0") > EngineInfo::Version("2.3.20"));
        QVERIFY(EngineInfo::Version("3.0.1") > EngineInfo::Version("3.0.0"));
        QVERIFY(EngineInfo::Version("3.1.0") > EngineInfo::Version("3.0.20"));
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        QVERIFY(copyKeyrings(gpgHome, mDir.path()));
        qputenv("GNUPGHOME", mDir.path().toUtf8());
    }

private:
    QTemporaryDir mDir;
};

QTEST_MAIN(TestVarious)

#include "t-various.moc"

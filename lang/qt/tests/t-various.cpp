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

#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include <QTemporaryDir>
#include "keylistjob.h"
#include "protocol.h"
#include <gpgme++/keylistresult.h>
#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include "dn.h"
#include <gpgme++/data.h>
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
        hookUpPassphraseProvider(ctx);

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

    void testSetExpire()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.22") {
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

        QVERIFY (key.subkey(0).expirationTime() == time_t(0));
        QVERIFY (key.subkey(1).expirationTime() == time_t(0));

        auto ctx = Context::createForProtocol(key.protocol());
        QVERIFY (ctx);
        hookUpPassphraseProvider(ctx);

        // change expiration of the main key
        QVERIFY(!ctx->setExpire(key, 1000));
        delete ctx;
        key.update();

        QVERIFY (key.subkey(0).expirationTime() != time_t(0));
        QVERIFY (key.subkey(1).expirationTime() == time_t(0));
        time_t keyExpiration = key.subkey(0).expirationTime();

        // change expiration of all subkeys
        ctx = Context::createForProtocol(key.protocol());
        QVERIFY(!ctx->setExpire(key, 2000, std::vector<Subkey>(), Context::SetExpireAllSubkeys));
        delete ctx;
        key.update();

        QVERIFY (key.subkey(0).expirationTime() == keyExpiration);
        QVERIFY (key.subkey(1).expirationTime() != time_t(0));
        time_t subkeyExpiration = key.subkey(1).expirationTime();

        // change expiration of specific subkey(s)
        ctx = Context::createForProtocol(key.protocol());
        std::vector<Subkey> specificSubkeys;
        specificSubkeys.push_back(key.subkey(1));
        QVERIFY(!ctx->setExpire(key, 3000, specificSubkeys));
        delete ctx;
        key.update();

        QVERIFY (key.subkey(0).expirationTime() == keyExpiration);
        QVERIFY (key.subkey(1).expirationTime() != subkeyExpiration);

        // test error handling: calling setExpire() with the primary key as
        // subkey should fail with "subkey <primary key fpr> not found"
        ctx = Context::createForProtocol(key.protocol());
        std::vector<Subkey> primaryKey;
        primaryKey.push_back(key.subkey(0));
        const auto err = ctx->setExpire(key, 3000, primaryKey);
        QCOMPARE(err.code(), static_cast<int>(GPG_ERR_NOT_FOUND));
        delete ctx;
    }

    void testSignKeyWithoutExpiration()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the signing key (alfa@example.net)
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!seckey.isNull());

        // Get the target key (Bob / Bravo Test)
        auto target = ctx->key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", err, false);
        QVERIFY(!err);
        QVERIFY(!target.isNull());
        QVERIFY(target.numUserIDs() > 0);

        // Create the job
        auto job = std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
        QVERIFY(job);
        hookUpPassphraseProvider(job.get());

        // Set up the job
        job->setExportable(true);
        job->setSigningKey(seckey);
        job->setDupeOk(true);

        connect(job.get(), &SignKeyJob::result,
                this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                    Q_EMIT asyncDone();
                    if (err2) {
                        if (err2.code() == GPG_ERR_GENERAL) {
                            QFAIL(qPrintable(QString("The SignKeyJob failed with '%1'.\n"
                                "Hint: Run with GPGMEPP_INTERACTOR_DEBUG=stderr to debug the edit interaction.").arg(err2.asString())));
                        } else {
                            QFAIL(qPrintable(QString("The SignKeyJob failed with '%1'.").arg(err2.asString())));
                        }
                    }
                });

        job->start(target);
        QSignalSpy spy{this, &TestVarious::asyncDone};
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the signature should have been added.
        target.update();
        const auto keySignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
        QVERIFY(keySignature.neverExpires());
    }

    void testSignKeyWithExpiration()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the signing key (alfa@example.net)
        auto seckey = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!seckey.isNull());

        // Get the target key (Bob / Bravo Test)
        auto target = ctx->key("D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2", err, false);
        QVERIFY(!err);
        QVERIFY(!target.isNull());
        QVERIFY(target.numUserIDs() > 0);

        // Create the job
        auto job = std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
        QVERIFY(job);
        hookUpPassphraseProvider(job.get());

        // Set up the job
        job->setExportable(true);
        job->setSigningKey(seckey);
        job->setDupeOk(true);
        job->setExpirationDate(QDate{2222, 2, 22});

        connect(job.get(), &SignKeyJob::result,
                this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                    Q_EMIT asyncDone();
                    if (err2) {
                        if (err2.code() == GPG_ERR_GENERAL) {
                            QFAIL(qPrintable(QString("The SignKeyJob failed with '%1'.\n"
                                "Hint: Run with GPGMEPP_INTERACTOR_DEBUG=stderr to debug the edit interaction.").arg(err2.asString())));
                        } else {
                            QFAIL(qPrintable(QString("The SignKeyJob failed with '%1'.").arg(err2.asString())));
                        }
                    }
                });

        job->start(target);
        QSignalSpy spy{this, &TestVarious::asyncDone};
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        // At this point the signature should have been added.
        target.update();
        const auto keySignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
        QVERIFY(!keySignature.neverExpires());
        const auto expirationDate = QDateTime::fromSecsSinceEpoch(uint_least32_t(keySignature.expirationTime())).date();
        // expiration date is capped at 2106-02-05; we also allow 2106-02-04 as expiration date because for locations that use DST
        // the expiration date may be 2106-02-04-23:xx:xx (in local non-DST time) if the current time is 00:xx::xx (in local DST time)
        const auto expectedExpirationRange = std::make_pair(QDate{2106, 2, 4}, QDate{2106, 2, 5});
        QVERIFY2(expirationDate >= expectedExpirationRange.first,
                 ("\n   Actual  : " + expirationDate.toString(Qt::ISODate).toLatin1() +
                  "\n   Expected: " + expectedExpirationRange.first.toString(Qt::ISODate).toLatin1()).constData());
        QVERIFY2(expirationDate <= expectedExpirationRange.second,
                 ("\n   Actual  : " + expirationDate.toString(Qt::ISODate).toLatin1() +
                  "\n   Expected: " + expectedExpirationRange.second.toString(Qt::ISODate).toLatin1()).constData());
    }

    void testVersion()
    {
        QVERIFY(EngineInfo::Version("2.1.0") < EngineInfo::Version("2.1.1"));
        QVERIFY(EngineInfo::Version("2.1.10") < EngineInfo::Version("2.1.11"));
        QVERIFY(EngineInfo::Version("2.2.0") > EngineInfo::Version("2.1.19"));
        QVERIFY(EngineInfo::Version("1.0.0") < EngineInfo::Version("2.0.0"));
        QVERIFY(EngineInfo::Version("0.1.0") < EngineInfo::Version("1.0.0"));
        QVERIFY(!(EngineInfo::Version("2.0.0") < EngineInfo::Version("2.0.0")));
        QVERIFY(!(EngineInfo::Version("2.0.0") > EngineInfo::Version("2.0.0")));
        QVERIFY(EngineInfo::Version("3.0.0") > EngineInfo::Version("2.3.20"));
        QVERIFY(EngineInfo::Version("3.0.1") > EngineInfo::Version("3.0.0"));
        QVERIFY(EngineInfo::Version("3.1.0") > EngineInfo::Version("3.0.20"));

        QVERIFY(EngineInfo::Version("1.1.1") <= "2.0.0");
        QVERIFY(EngineInfo::Version("1.1.1") <= "1.2.0");
        QVERIFY(EngineInfo::Version("1.1.1") <= "1.1.2");
        QVERIFY(EngineInfo::Version("1.1.1") <= "1.1.1");
        QVERIFY(!(EngineInfo::Version("1.1.1") <= "1.1.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") <= "1.0.9"));
        QVERIFY(!(EngineInfo::Version("1.1.1") <= "0.9.9"));

        QVERIFY(!(EngineInfo::Version("1.1.1") == "2.0.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") == "1.2.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") == "1.1.2"));
        QVERIFY(EngineInfo::Version("1.1.1") == "1.1.1");
        QVERIFY(!(EngineInfo::Version("1.1.1") == "1.1.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") == "1.0.9"));
        QVERIFY(!(EngineInfo::Version("1.1.1") == "0.9.9"));

        QVERIFY(EngineInfo::Version("1.1.1") != "2.0.0");
        QVERIFY(EngineInfo::Version("1.1.1") != "1.2.0");
        QVERIFY(EngineInfo::Version("1.1.1") != "1.1.2");
        QVERIFY(!(EngineInfo::Version("1.1.1") != "1.1.1"));
        QVERIFY(EngineInfo::Version("1.1.1") != "1.1.0");
        QVERIFY(EngineInfo::Version("1.1.1") != "1.0.9");
        QVERIFY(EngineInfo::Version("1.1.1") != "0.9.9");

        QVERIFY(!(EngineInfo::Version("1.1.1") >= "2.0.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") >= "1.2.0"));
        QVERIFY(!(EngineInfo::Version("1.1.1") >= "1.1.2"));
        QVERIFY(EngineInfo::Version("1.1.1") >= "1.1.1");
        QVERIFY(EngineInfo::Version("1.1.1") >= "1.1.0");
        QVERIFY(EngineInfo::Version("1.1.1") >= "1.0.9");
        QVERIFY(EngineInfo::Version("1.1.1") >= "0.9.9");
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
            conf.write("allow-weak-key-signatures");
        }
        conf.close();
    }

private:
    QTemporaryDir mDir;
};

QTEST_MAIN(TestVarious)

#include "t-various.moc"

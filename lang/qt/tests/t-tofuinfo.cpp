/* t-tofuinfo.cpp

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
#include <QDebug>
#include <QTest>
#include <QTemporaryDir>
#include <QSignalSpy>

#include "protocol.h"
#include <gpgme++/tofuinfo.h>
#include "tofupolicyjob.h"
#include "verifyopaquejob.h"
#include <gpgme++/verificationresult.h>
#include <gpgme++/signingresult.h>
#include "importjob.h"
#include <gpgme++/importresult.h>
#include "keylistjob.h"
#include <gpgme++/keylistresult.h>
#include "signjob.h"
#include <gpgme++/key.h>

#include "t-support.h"
#include <gpgme++/engineinfo.h>
#include <gpgme++/context.h>
#include <iostream>

using namespace QGpgME;
using namespace GpgME;

static const char testMsg1[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n"
"GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n"
"y1kvP4y+8D5a11ang0udywsA\n"
"=Crq6\n"
"-----END PGP MESSAGE-----\n";

static const char conflictKey1[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
"\n"
"mDMEXDWgpxYJKwYBBAHaRw8BAQdAguVu4qkx8iw4eU+TQ4vvcKG7IdcZvbMhw3Zc\n"
"npGf0+u0GXRvZnVfY29uZmxpY3RAZXhhbXBsZS5jb22IkAQTFggAOBYhBO6ovNDG\n"
"nLzbR1TlMJYJ0fjlWbUrBQJcNaCnAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA\n"
"AAoJEJYJ0fjlWbUrLaMBALegwkv2+sEcmKZqxt8JscYvFiEuycv2+rKHaZA0eDoN\n"
"AP97W4XrJb5x49J5jDDdeko8k00uGqiiuAXJo27/i/phA7g4BFw1oKcSCisGAQQB\n"
"l1UBBQEBB0Crhw24E2lPBhd/y+ZFotQ/2TrYqkUQqGPmff8ofLziNgMBCAeIeAQY\n"
"FggAIBYhBO6ovNDGnLzbR1TlMJYJ0fjlWbUrBQJcNaCnAhsMAAoJEJYJ0fjlWbUr\n"
"/K8BAJWsa+tOZsJw7w5fz6O0We6Xx4Rt17jHf563G6wMcz9+AQDRsedJ7w4zYzS9\n"
"MFiJQ5aN0NDHMRtDFWAgCunVnJ3OBw==\n"
"=fZa5\n"
"-----END PGP PUBLIC KEY BLOCK-----\n";

static const char conflictKey2[] = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
"\n"
"mDMEXDWgixYJKwYBBAHaRw8BAQdAMWOhumYspcvEOTuesOSN4rvnJVOj/6qOWFTu\n"
"x+wPRra0GXRvZnVfY29uZmxpY3RAZXhhbXBsZS5jb22IkAQTFggAOBYhBA64G88Q\n"
"NPXztj8ID/FhC7tiGbeRBQJcNaCLAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheA\n"
"AAoJEPFhC7tiGbeRUt4A/2hf4Zgz+TYyfeH/4/ZtyL1JuZggqR1s5UopEx2Aiw10\n"
"AP405KiTd31TJQN8Ru+7bskPu0/mzLZMNkRvBNEdc5kbDLg4BFw1oIsSCisGAQQB\n"
"l1UBBQEBB0B5NtSrx7wDDKgwUe5Rxz0vRkaWLtyE0KbfE77oPy5DGAMBCAeIeAQY\n"
"FggAIBYhBA64G88QNPXztj8ID/FhC7tiGbeRBQJcNaCLAhsMAAoJEPFhC7tiGbeR\n"
"km0BAP8TQwraipqb1pJlLsEgDXeM5Jocz4fuePD78BsOBtORAP9gpCyKXdyJYGlA\n"
"qjmG356yG6pCK9aPckTZ9IViPiHWCw==\n"
"=tn3Q\n"
"-----END PGP PUBLIC KEY BLOCK-----\n";

static const char conflictMsg1[] = "-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCE2jfPij6eRW7UZTwsnMcSYLnT0Ki0uUXD3C1XILFHk6ihlYRDjYJAV\n"
"U2R5t2LPhWNz9tx2D3lqANPEygTSwcDFKQAT+RjG8M9of873hQrMpinBVwKYv+rq\n"
"XGmYW+ZcZJ+133KDq+itzlxGhg3L2X/6Khj+2Hd+He+KnXtunF2wNWxl7849e/Sy\n"
"v6tc+8MBAA==\n"
"=fZLe\n"
"-----END PGP MESSAGE-----\n";

static const char conflictMsg2[] = "-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCH2MZF7d5Lk9omMp4WTGGJMFwZ4lRaXKLj7hSpklihydZSyMIhxMMiK\n"
"KbLw7ZA+L2Dy9fM2ew5+mCZWJpAOBi5OAZhIUhIjw7bV+xS+cR0quqhmcY2Dl3WW\n"
"8Ufr+rRNufOPyIdoO6nEXGH47/B+E1+oxS6e5f5n7MJ3aHBO+s345sipGV/4f665\n"
"9mmiGjsA\n"
"=8oJA\n"
"-----END PGP MESSAGE-----\n";

class TofuInfoTest: public QGpgMETest
{
    Q_OBJECT

private:
    bool testSupported()
    {
        static bool initialized, supported;
        if (initialized) {
            return supported;
        }
        initialized = true;
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.16") {
            return false;
        }
        // If the keylist fails here this means that gnupg does not
        // support tofu at all. It can be disabled at compile time. So no
        // tests.
        auto *job = openpgp()->keyListJob(false, false, false);
        job->addMode(GpgME::WithTofu);
        std::vector<GpgME::Key> keys;
        job->exec(QStringList() << QStringLiteral("zulu@example.net"), true, keys);
        delete job;
        supported = !keys.empty();
        return supported;
    }

    void testTofuCopy(TofuInfo other, const TofuInfo &orig)
    {
        QVERIFY(!orig.isNull());
        QVERIFY(!other.isNull());
        QVERIFY(orig.signLast() == other.signLast());
        QVERIFY(orig.signCount() == other.signCount());
        QVERIFY(orig.validity() == other.validity());
        QVERIFY(orig.policy() == other.policy());
    }

    void signAndVerify(const QString &what, const GpgME::Key &key, int expected)
    {
        auto job = openpgp()->signJob();
        hookUpPassphraseProvider(job);

        std::vector<Key> keys;
        keys.push_back(key);
        QByteArray signedData;
        auto sigResult = job->exec(keys, what.toUtf8(), NormalSignatureMode, signedData);
        delete job;

        QVERIFY(!sigResult.error());
        foreach (const auto uid, keys[0].userIDs()) {
            auto info = uid.tofuInfo();
            QVERIFY(info.signCount() == expected - 1);
        }

        auto verifyJob = openpgp()->verifyOpaqueJob();
        QByteArray verified;

        auto result = verifyJob->exec(signedData, verified);
        delete verifyJob;

        QVERIFY(!result.error());
        QVERIFY(verified == what.toUtf8());

        QVERIFY(result.numSignatures() == 1);
        auto sig = result.signatures()[0];

        auto key2 = sig.key();
        QVERIFY(!key.isNull());
        QVERIFY(!strcmp (key2.primaryFingerprint(), key.primaryFingerprint()));
        QVERIFY(!strcmp (key.primaryFingerprint(), sig.fingerprint()));
        auto stats = key2.userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        if (stats.signCount() != expected) {
            std::cout << "################ Key before verify: "
                      << key
                      << "################ Key after verify: "
                      << key2;
        }
        QVERIFY(stats.signCount() == expected);
    }

private Q_SLOTS:
    void testTofuNull()
    {
        if (!testSupported()) {
            return;
        }
        TofuInfo tofu;
        QVERIFY(tofu.isNull());
        QVERIFY(!tofu.description());
        QVERIFY(!tofu.signCount());
        QVERIFY(!tofu.signLast());
        QVERIFY(!tofu.signFirst());
        QVERIFY(tofu.validity() == TofuInfo::ValidityUnknown);
        QVERIFY(tofu.policy() == TofuInfo::PolicyUnknown);
    }

    void testTofuInfo()
    {
        if (!testSupported()) {
            return;
        }
        auto *job = openpgp()->verifyOpaqueJob(true);
        const QByteArray data1(testMsg1);
        QByteArray plaintext;

        auto ctx = Job::context(job);
        QVERIFY(ctx);
        ctx->setSender("alfa@example.net");

        auto result = job->exec(data1, plaintext);
        delete job;

        QVERIFY(!result.isNull());
        QVERIFY(!result.error());
        QVERIFY(!strcmp(plaintext.constData(), "Just GNU it!\n"));

        QVERIFY(result.numSignatures() == 1);
        Signature sig = result.signatures()[0];
        /* TOFU is always marginal */
        QVERIFY(sig.validity() == Signature::Marginal);

        auto stats = sig.key().userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        QVERIFY(sig.key().primaryFingerprint());
        QVERIFY(sig.fingerprint());
        QVERIFY(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        QVERIFY(stats.signFirst() == stats.signLast());
        QVERIFY(stats.signCount() == 1);
        QVERIFY(stats.policy() == TofuInfo::PolicyAuto);
        QVERIFY(stats.validity() == TofuInfo::LittleHistory);

        testTofuCopy(stats, stats);

        /* Another verify */

        job = openpgp()->verifyOpaqueJob(true);
        result = job->exec(data1, plaintext);
        delete job;

        QVERIFY(!result.isNull());
        QVERIFY(!result.error());

        QVERIFY(result.numSignatures() == 1);
        sig = result.signatures()[0];
        /* TOFU is always marginal */
        QVERIFY(sig.validity() == Signature::Marginal);

        stats = sig.key().userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        QVERIFY(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        QVERIFY(stats.signFirst() == stats.signLast());
        QVERIFY(stats.signCount() == 1);
        QVERIFY(stats.policy() == TofuInfo::PolicyAuto);
        QVERIFY(stats.validity() == TofuInfo::LittleHistory);

        /* Verify that another call yields the same result */
        job = openpgp()->verifyOpaqueJob(true);
        result = job->exec(data1, plaintext);
        delete job;

        QVERIFY(!result.isNull());
        QVERIFY(!result.error());

        QVERIFY(result.numSignatures() == 1);
        sig = result.signatures()[0];
        /* TOFU is always marginal */
        QVERIFY(sig.validity() == Signature::Marginal);

        stats = sig.key().userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        QVERIFY(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        QVERIFY(stats.signFirst() == stats.signLast());
        QVERIFY(stats.signCount() == 1);
        QVERIFY(stats.policy() == TofuInfo::PolicyAuto);
        QVERIFY(stats.validity() == TofuInfo::LittleHistory);
    }

    void testTofuSignCount()
    {
        if (!testSupported()) {
            return;
        }
        auto *job = openpgp()->keyListJob(false, false, false);
        job->addMode(GpgME::WithTofu);
        std::vector<GpgME::Key> keys;
        GpgME::KeyListResult result = job->exec(QStringList() << QStringLiteral("zulu@example.net"),
                                                true, keys);
        delete job;
        QVERIFY(!keys.empty());
        Key key = keys[0];
        QVERIFY(!key.isNull());

        /* As we sign & verify quickly here we need different
         * messages to avoid having them treated as the same
         * message if they were created within the same second.
         * Alternatively we could use the same message and wait
         * a second between each call. But this would slow down
         * the testsuite. */
        signAndVerify(QStringLiteral("Hello"), key, 1);
        key.update();
        signAndVerify(QStringLiteral("Hello2"), key, 2);
        key.update();
        signAndVerify(QStringLiteral("Hello3"), key, 3);
        key.update();
        signAndVerify(QStringLiteral("Hello4"), key, 4);
    }

    void testTofuKeyList()
    {
        if (!testSupported()) {
            return;
        }

        /* First check that the key has no tofu info. */
        auto *job = openpgp()->keyListJob(false, false, false);
        std::vector<GpgME::Key> keys;
        auto result = job->exec(QStringList() << QStringLiteral("zulu@example.net"),
                                                 true, keys);
        delete job;
        QVERIFY(!keys.empty());
        auto key = keys[0];
        QVERIFY(!key.isNull());
        QVERIFY(key.userID(0).tofuInfo().isNull());
        auto keyCopy = key;
        keyCopy.update();
        auto sigCnt = keyCopy.userID(0).tofuInfo().signCount();
        signAndVerify(QStringLiteral("Hello5"), keyCopy,
                      sigCnt + 1);
        keyCopy.update();
        signAndVerify(QStringLiteral("Hello6"), keyCopy,
                      sigCnt + 2);

        /* Now another one but with tofu */
        job = openpgp()->keyListJob(false, false, false);
        job->addMode(GpgME::WithTofu);
        result = job->exec(QStringList() << QStringLiteral("zulu@example.net"),
                           true, keys);
        delete job;
        QVERIFY(!result.error());
        QVERIFY(!keys.empty());
        auto key2 = keys[0];
        QVERIFY(!key2.isNull());
        auto info = key2.userID(0).tofuInfo();
        QVERIFY(!info.isNull());
        QVERIFY(info.signCount());
    }

    void testTofuPolicy()
    {
        if (!testSupported()) {
            return;
        }

        /* First check that the key has no tofu info. */
        auto *job = openpgp()->keyListJob(false, false, false);
        std::vector<GpgME::Key> keys;
        job->addMode(GpgME::WithTofu);
        auto result = job->exec(QStringList() << QStringLiteral("bravo@example.net"),
                                                 false, keys);

        if (keys.empty()) {
            qDebug() << "bravo@example.net not found";
            qDebug() << "Error: " << result.error().asString();
            const auto homedir = QString::fromLocal8Bit(qgetenv("GNUPGHOME"));
            qDebug() << "Homedir is: " << homedir;
            QFileInfo fi(homedir + "/pubring.gpg");
            qDebug () << "pubring exists: " << fi.exists() << " readable? "
                      << fi.isReadable() << " size: " << fi.size();
            QFileInfo fi2(homedir + "/pubring.kbx");
            qDebug () << "keybox exists: " << fi2.exists() << " readable? "
                      << fi2.isReadable() << " size: " << fi2.size();

            result = job->exec(QStringList(), false, keys);
            foreach (const auto key, keys) {
                qDebug() << "Key: " << key.userID(0).name() << " <"
                         << key.userID(0).email()
                         << ">\n fpr: " << key.primaryFingerprint();
            }
        }
        QVERIFY(!result.error());
        QVERIFY(!keys.empty());
        auto key = keys[0];
        QVERIFY(!key.isNull());
        QVERIFY(key.userID(0).tofuInfo().policy() != TofuInfo::PolicyBad);
        auto *tofuJob = openpgp()->tofuPolicyJob();
        auto err = tofuJob->exec(key, TofuInfo::PolicyBad);
        QVERIFY(!err);
        result = job->exec(QStringList() << QStringLiteral("bravo@example.net"),
                                            false, keys);
        QVERIFY(!keys.empty());
        key = keys[0];
        QVERIFY(key.userID(0).tofuInfo().policy() == TofuInfo::PolicyBad);
        err = tofuJob->exec(key, TofuInfo::PolicyGood);

        result = job->exec(QStringList() << QStringLiteral("bravo@example.net"),
                                            false, keys);
        key = keys[0];
        QVERIFY(key.userID(0).tofuInfo().policy() == TofuInfo::PolicyGood);
        delete tofuJob;
        delete job;
    }

    void testTofuConflict()
    {
        if (!testSupported()) {
            return;
        }

        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.19") {
            return;
        }

        // Import key 1
        auto importjob = openpgp()->importJob();
        connect(importjob, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(!result.imports().empty());
            QVERIFY(result.numImported());
            Q_EMIT asyncDone();
        });
        importjob->start(QByteArray(conflictKey1));
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait());

        // Verify Message 1
        const QByteArray signedData(conflictMsg1);
        auto verifyJob = openpgp()->verifyOpaqueJob(true);
        QByteArray verified;
        auto result = verifyJob->exec(signedData, verified);
        delete verifyJob;

        QVERIFY(!result.isNull());
        QVERIFY(!result.error());

        QVERIFY(result.numSignatures() == 1);
        auto sig = result.signatures()[0];
        QVERIFY(sig.validity() == Signature::Marginal);

        auto stats = sig.key().userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        QVERIFY(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        QVERIFY(stats.signFirst() == stats.signLast());
        QVERIFY(stats.signCount() == 1);
        QVERIFY(stats.policy() == TofuInfo::PolicyAuto);
        QVERIFY(stats.validity() == TofuInfo::LittleHistory);

        // Import key 2
        importjob = openpgp()->importJob();
        connect(importjob, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(!result.imports().empty());
            QVERIFY(result.numImported());
            Q_EMIT asyncDone();
        });
        importjob->start(QByteArray(conflictKey2));
        QSignalSpy spy2 (this, SIGNAL(asyncDone()));
        QVERIFY(spy2.wait());

        // Verify Message 2
        const QByteArray signedData2(conflictMsg2);
        QByteArray verified2;
        verifyJob = openpgp()->verifyOpaqueJob(true);
        result = verifyJob->exec(signedData2, verified2);
        delete verifyJob;

        QVERIFY(!result.isNull());
        QVERIFY(!result.error());

        QVERIFY(result.numSignatures() == 1);
        sig = result.signatures()[0];
        QVERIFY(sig.validity() == Signature::Unknown);
        // TODO activate when implemented
        // QVERIFY(sig.summary() == Signature::TofuConflict);

        stats = sig.key().userID(0).tofuInfo();
        QVERIFY(!stats.isNull());
        QVERIFY(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        QVERIFY(stats.signFirst() == stats.signLast());
        QVERIFY(stats.signCount() == 1);
        QVERIFY(stats.policy() == TofuInfo::PolicyAsk);
        QVERIFY(stats.validity() == TofuInfo::Conflict);
    }


    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        QVERIFY(mDir.isValid());
        QFile conf(mDir.path() + QStringLiteral("/gpg.conf"));
        QVERIFY(conf.open(QIODevice::WriteOnly));
        conf.write("trust-model tofu+pgp");
        conf.close();
        QFile agentConf(mDir.path() + QStringLiteral("/gpg-agent.conf"));
        QVERIFY(agentConf.open(QIODevice::WriteOnly));
        agentConf.write("allow-loopback-pinentry");
        agentConf.close();
        QVERIFY(copyKeyrings(gpgHome, mDir.path()));
    }
private:
    QTemporaryDir mDir;

};

QTEST_MAIN(TofuInfoTest)

#include "t-tofuinfo.moc"

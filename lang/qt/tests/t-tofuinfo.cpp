/* t-tofuinfo.cpp

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
#include <QDebug>
#include <QTest>
#include <QTemporaryDir>
#include "protocol.h"
#include "tofuinfo.h"
#include "verifyopaquejob.h"
#include "verificationresult.h"
#include "signingresult.h"
#include "keylistjob.h"
#include "keylistresult.h"
#include "qgpgmesignjob.h"
#include "key.h"
#include "t-support.h"
#include "engineinfo.h"
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

class TofuInfoTest: public QGpgMETest
{
    Q_OBJECT

    bool testSupported()
    {
        return !(GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.16");
    }

    void testTofuCopy(TofuInfo other, const TofuInfo &orig)
    {
        Q_ASSERT(!orig.isNull());
        Q_ASSERT(!other.isNull());
        Q_ASSERT(orig.lastSeen() == other.lastSeen());
        Q_ASSERT(orig.signCount() == other.signCount());
        Q_ASSERT(orig.validity() == other.validity());
        Q_ASSERT(orig.policy() == other.policy());
    }

    void signAndVerify(const QString &what, const GpgME::Key &key, int expected)
    {
        Context *ctx = Context::createForProtocol(OpenPGP);
        TestPassphraseProvider provider;
        ctx->setPassphraseProvider(&provider);
        ctx->setPinentryMode(Context::PinentryLoopback);
        auto *job = new QGpgMESignJob(ctx);

        std::vector<Key> keys;
        keys.push_back(key);
        QByteArray signedData;
        auto sigResult = job->exec(keys, what.toUtf8(), NormalSignatureMode, signedData);
        delete job;

        Q_ASSERT(!sigResult.error());
        foreach (const auto uid, keys[0].userIDs()) {
            auto info = uid.tofuInfo();
            Q_ASSERT(info.signCount() == expected - 1);
        }

        auto verifyJob = openpgp()->verifyOpaqueJob();
        QByteArray verified;

        auto result = verifyJob->exec(signedData, verified);
        delete verifyJob;

        Q_ASSERT(!result.error());
        Q_ASSERT(verified == what.toUtf8());

        Q_ASSERT(result.numSignatures() == 1);
        auto sig = result.signatures()[0];

        auto key2 = sig.key();
        Q_ASSERT(!key.isNull());
        Q_ASSERT(!strcmp (key2.primaryFingerprint(), key.primaryFingerprint()));
        Q_ASSERT(!strcmp (key.primaryFingerprint(), sig.fingerprint()));
        auto stats = key2.userID(0).tofuInfo();
        Q_ASSERT(!stats.isNull());
        if (stats.signCount() != expected) {
            std::cout << "################ Key before verify: "
                      << key
                      << "################ Key after verify: "
                      << key2;
        }
        Q_ASSERT(stats.signCount() == expected);
    }

private Q_SLOTS:
    void testTofuNull()
    {
        if (!testSupported()) {
            return;
        }
        TofuInfo tofu;
        Q_ASSERT(tofu.isNull());
        Q_ASSERT(!tofu.description());
        Q_ASSERT(!tofu.signCount());
        Q_ASSERT(!tofu.lastSeen());
        Q_ASSERT(!tofu.firstSeen());
        Q_ASSERT(tofu.validity() == TofuInfo::ValidityUnknown);
        Q_ASSERT(tofu.policy() == TofuInfo::PolicyUnknown);
    }

    void testTofuInfo()
    {
        if (!testSupported()) {
            return;
        }
        auto *job = openpgp()->verifyOpaqueJob(true);
        const QByteArray data1(testMsg1);
        QByteArray plaintext;

        auto result = job->exec(data1, plaintext);
        delete job;

        Q_ASSERT(!result.isNull());
        Q_ASSERT(!result.error());
        Q_ASSERT(!strcmp(plaintext.constData(), "Just GNU it!\n"));

        Q_ASSERT(result.numSignatures() == 1);
        Signature sig = result.signatures()[0];
        /* TOFU is always marginal */
        Q_ASSERT(sig.validity() == Signature::Marginal);

        auto stats = sig.key().userID(0).tofuInfo();
        Q_ASSERT(!stats.isNull());
        Q_ASSERT(sig.key().primaryFingerprint());
        Q_ASSERT(sig.fingerprint());
        Q_ASSERT(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        Q_ASSERT(stats.firstSeen() == stats.lastSeen());
        Q_ASSERT(stats.signCount() == 1);
        Q_ASSERT(stats.policy() == TofuInfo::PolicyAuto);
        Q_ASSERT(stats.validity() == TofuInfo::LittleHistory);

        testTofuCopy(stats, stats);

        /* Another verify */

        job = openpgp()->verifyOpaqueJob(true);
        result = job->exec(data1, plaintext);
        delete job;

        Q_ASSERT(!result.isNull());
        Q_ASSERT(!result.error());

        Q_ASSERT(result.numSignatures() == 1);
        sig = result.signatures()[0];
        /* TOFU is always marginal */
        Q_ASSERT(sig.validity() == Signature::Marginal);

        stats = sig.key().userID(0).tofuInfo();
        Q_ASSERT(!stats.isNull());
        Q_ASSERT(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        Q_ASSERT(stats.firstSeen() == stats.lastSeen());
        Q_ASSERT(stats.signCount() == 1);
        Q_ASSERT(stats.policy() == TofuInfo::PolicyAuto);
        Q_ASSERT(stats.validity() == TofuInfo::LittleHistory);

        /* Verify that another call yields the same result */
        job = openpgp()->verifyOpaqueJob(true);
        result = job->exec(data1, plaintext);
        delete job;

        Q_ASSERT(!result.isNull());
        Q_ASSERT(!result.error());

        Q_ASSERT(result.numSignatures() == 1);
        sig = result.signatures()[0];
        /* TOFU is always marginal */
        Q_ASSERT(sig.validity() == Signature::Marginal);

        stats = sig.key().userID(0).tofuInfo();
        Q_ASSERT(!stats.isNull());
        Q_ASSERT(!strcmp(sig.key().primaryFingerprint(), sig.fingerprint()));
        Q_ASSERT(stats.firstSeen() == stats.lastSeen());
        Q_ASSERT(stats.signCount() == 1);
        Q_ASSERT(stats.policy() == TofuInfo::PolicyAuto);
        Q_ASSERT(stats.validity() == TofuInfo::LittleHistory);
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
        Q_ASSERT(!keys.empty());
        Key key = keys[0];
        Q_ASSERT(!key.isNull());

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
        Q_ASSERT(!keys.empty());
        auto key = keys[0];
        Q_ASSERT(!key.isNull());
        Q_ASSERT(key.userID(0).tofuInfo().isNull());
        auto keyCopy = key;
        keyCopy.update();
        auto sigCnt = keyCopy.userID(0).tofuInfo().signCount();
        signAndVerify(QStringLiteral("Hello"), keyCopy,
                      sigCnt + 1);
        keyCopy.update();
        /* For some reason if you remove the " World" part of
         * the next message the test fails. */
        signAndVerify(QStringLiteral("Hello World"), keyCopy,
                      sigCnt + 2);

        /* Now another one but with tofu */
        job = openpgp()->keyListJob(false, false, false);
        job->addMode(GpgME::WithTofu);
        result = job->exec(QStringList() << QStringLiteral("zulu@example.net"),
                           true, keys);
        delete job;
        Q_ASSERT(!result.error());
        Q_ASSERT(!keys.empty());
        auto key2 = keys[0];
        Q_ASSERT(!key2.isNull());
        auto info = key2.userID(0).tofuInfo();
        Q_ASSERT(!info.isNull());
        Q_ASSERT(info.signCount());
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        Q_ASSERT(mDir.isValid());
        QFile conf(mDir.path() + QStringLiteral("/gpg.conf"));
        Q_ASSERT(conf.open(QIODevice::WriteOnly));
        conf.write("trust-model tofu+pgp");
        conf.close();
        QFile agentConf(mDir.path() + QStringLiteral("/gpg-agent.conf"));
        Q_ASSERT(agentConf.open(QIODevice::WriteOnly));
        agentConf.write("allow-loopback-pinentry");
        agentConf.close();
        Q_ASSERT(copyKeyrings(gpgHome, mDir.path()));
    }
private:
    QTemporaryDir mDir;

};

QTEST_MAIN(TofuInfoTest)

#include "t-tofuinfo.moc"

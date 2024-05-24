/* t-keylist.cpp

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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include <QDebug>
#include <QTest>
#include <QSignalSpy>
#include <QMap>
#include "keylistjob.h"
#include "listallkeysjob.h"
#include "qgpgmebackend.h"
#include <gpgme++/keylistresult.h>

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>

#include <memory>

#include "t-support.h"

using namespace QGpgME;
using namespace GpgME;

class KeyListTest : public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void testSingleKeyListSync()
    {
        KeyListJob *job = openpgp()->keyListJob(false, false, false);
        std::vector<GpgME::Key> keys;
        GpgME::KeyListResult result = job->exec(QStringList() << QStringLiteral("alfa@example.net"),
                                                false, keys);
        delete job;
        QVERIFY (!result.error());
        QVERIFY (keys.size() == 1);
        const QString kId = QLatin1String(keys.front().keyID());
        QVERIFY (kId == QStringLiteral("2D727CC768697734"));

        QVERIFY (keys[0].subkeys().size() == 2);
        QVERIFY (keys[0].subkeys()[0].publicKeyAlgorithm() == Subkey::AlgoDSA);
        QVERIFY (keys[0].subkeys()[1].publicKeyAlgorithm() == Subkey::AlgoELG_E);
    }

    // This test can help with valgrind to check for memleaks when handling
    // keys
    void testGetKey()
    {
        GpgME::Key key;
        {
            auto ctx = std::unique_ptr<GpgME::Context> (GpgME::Context::createForProtocol(GpgME::OpenPGP));
            ctx->setKeyListMode (GpgME::KeyListMode::Local |
                    GpgME::KeyListMode::Signatures |
                    GpgME::KeyListMode::Validate |
                    GpgME::KeyListMode::WithTofu);
            GpgME::Error err;
            key = ctx->key ("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, false);
        }
        QVERIFY(key.primaryFingerprint());
        QVERIFY(!strcmp(key.primaryFingerprint(), "A0FF4590BB6122EDEF6E3C542D727CC768697734"));
        {
            auto ctx = std::unique_ptr<GpgME::Context> (GpgME::Context::createForProtocol(GpgME::OpenPGP));
            ctx->setKeyListMode (GpgME::KeyListMode::Local |
                    GpgME::KeyListMode::Signatures |
                    GpgME::KeyListMode::Validate |
                    GpgME::KeyListMode::WithTofu);
            GpgME::Error err;
            key = ctx->key ("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, false);
        }
        QVERIFY(key.primaryFingerprint());
        QVERIFY(!strcmp(key.primaryFingerprint(), "A0FF4590BB6122EDEF6E3C542D727CC768697734"));
    }

    void testPubkeyAlgoAsString()
    {
        static const QMap<Subkey::PubkeyAlgo, QString> expected {
            { Subkey::AlgoRSA,    QStringLiteral("RSA") },
            { Subkey::AlgoRSA_E,  QStringLiteral("RSA-E") },
            { Subkey::AlgoRSA_S,  QStringLiteral("RSA-S") },
            { Subkey::AlgoELG_E,  QStringLiteral("ELG-E") },
            { Subkey::AlgoDSA,    QStringLiteral("DSA") },
            { Subkey::AlgoECC,    QStringLiteral("ECC") },
            { Subkey::AlgoELG,    QStringLiteral("ELG") },
            { Subkey::AlgoECDSA,  QStringLiteral("ECDSA") },
            { Subkey::AlgoECDH,   QStringLiteral("ECDH") },
            { Subkey::AlgoEDDSA,  QStringLiteral("EdDSA") },
            { Subkey::AlgoUnknown, QString() }
        };
        for (Subkey::PubkeyAlgo algo : expected.keys()) {
            QVERIFY(QString::fromUtf8(Subkey::publicKeyAlgorithmAsString(algo)) ==
                     expected.value(algo));
        }
    }

    void testKeyListAsync()
    {
        KeyListJob *job = openpgp()->keyListJob();
        connect(job, &KeyListJob::result, job, [this, job](KeyListResult, std::vector<Key> keys, QString, Error)
        {
            QVERIFY(keys.size() == 1);
            Q_EMIT asyncDone();
        });
        job->start(QStringList() << "alfa@example.net");
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

    void testListAllKeysSync()
    {
        const auto accumulateFingerprints = [](std::vector<std::string> &v, const Key &key) { v.push_back(std::string(key.primaryFingerprint())); return v; };

        ListAllKeysJob *job = openpgp()->listAllKeysJob(/* includeSigs= */false, /* validate= */false);
        std::vector<GpgME::Key> pubKeys, secKeys;
        GpgME::KeyListResult result = job->exec(pubKeys, secKeys, /* mergeKeys= */false); // mergeKeys is unused for GnuPG >= 2.1
        delete job;
        QVERIFY(!result.error());

        QCOMPARE(secKeys.size(), static_cast<decltype(secKeys.size())>(2));
        std::vector<std::string> secKeyFingerprints = std::accumulate(secKeys.begin(), secKeys.end(), std::vector<std::string>(), accumulateFingerprints);
        QCOMPARE(secKeyFingerprints, std::vector<std::string>({
                "23FD347A419429BACCD5E72D6BC4778054ACD246",
                "A0FF4590BB6122EDEF6E3C542D727CC768697734"
        }));
        QVERIFY(secKeys[0].hasSecret());
        if (!(GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.0")) {
            QVERIFY(secKeys[0].subkeys()[0].keyGrip());
        }

        QCOMPARE(pubKeys.size(), static_cast<decltype(pubKeys.size())>(26));
        std::vector<std::string> pubKeyFingerprints = std::accumulate(pubKeys.begin(), pubKeys.end(), std::vector<std::string>(), accumulateFingerprints);
        QCOMPARE(pubKeyFingerprints, std::vector<std::string>({
                "045B2334ADD69FC221076841A5E67F7FA3AE3EA1",
                "04C1DF62EFA0EBB00519B06A8979A6C5567FB34A",
                "0DBCAD3F08843B9557C6C4D4A94C0F75653244D6",
                "1DDD28CEF714F5B03B8C246937CAB51FB79103F8",
                "23FD347A419429BACCD5E72D6BC4778054ACD246",
                "2686AA191A278013992C72EBBE794852BE5CF886",
                "3531152DE293E26A07F504BC318C1FAEFAEF6D1B",
                "38FBE1E4BF6A5E1242C8F6A13BDBEDB1777FBED3",
                "3FD11083779196C2ECDD9594AD1B0FAD43C2D0C7",
                "43929E89F8F79381678CAE515F6356BA6D9732AC",
                "56D33268F7FE693FBB594762D4BF57F37372E243",
                "5AB9D6D7BAA1C95B3BAA3D9425B00FD430CEC684",
                "61EE841A2A27EB983B3B3C26413F4AF31AFDAB6C",
                "6560C59C43D031C54D7C588EEBA9F240EB9DC9E6",
                "6FAA9C201E5E26DCBAEC39FD5D15E01D3FF13206",
                "9E91CBB11E4D4135583EF90513DB965534C6E3F1",
                "A0FF4590BB6122EDEF6E3C542D727CC768697734",
                "A7969DA1C3297AA96D49843F1C67EC133C661C84",
                "C9C07DCC6621B9FB8D071B1D168410A48FC282E6",
                "CD538D6CC9FB3D745ECDA5201FE8FC6F04259677",
                "D695676BDCEDCC2CDD6152BCFE180B1DA9E3B0B2",
                "E8143C489C8D41124DC40D0B47AF4B6961F04784",
                "E8D6C90B683B0982BD557A99DEF0F7B8EC67DBDE",
                "ECAC774F4EEEB0620767044A58CB9A4C85A81F38",
                "ED9B316F78644A58D042655A9EEF34CD4B11B25F",
                "F8F1EDC73995AB739AD54B380C820C71D2699313"
        }));
        if (!(GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.1.0")) {
            // with GnuPG >= 2.1 the job always lists keys with --with-keygrip and --with-secret,
            // i.e. the key grips and information about secret keys are always available
            QVERIFY(!pubKeys[0].hasSecret());
            QVERIFY(pubKeys[0].subkeys()[0].keyGrip());

            QVERIFY(pubKeys[4].hasSecret());
            QVERIFY(pubKeys[4].subkeys()[0].keyGrip());
        }
    }
};

QTEST_MAIN(KeyListTest)

#include "t-keylist.moc"

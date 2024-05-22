/* t-wkspublish.cpp

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
#include <QSignalSpy>
#include <QTemporaryDir>
#include "wkspublishjob.h"
#include "keygenerationjob.h"
#include <gpgme++/keygenerationresult.h>
#include "importjob.h"
#include <gpgme++/importresult.h>
#include "protocol.h"
#include <gpgme++/engineinfo.h>

#include "t-support.h"

using namespace QGpgME;
using namespace GpgME;

//#define DO_ONLINE_TESTS

#define TEST_ADDRESS "testuser2@test.gnupg.org"

static const char *testSecKey =
"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
"\n"
"lHgEV77hVhMJKyQDAwIIAQEHAgMEN3qKqBr9EecnfUnpw8RS8DHAjJqhwm2HAoEE\n"
"3yfQQ9w8uB/bKm5dqW4HML3JWRH8YoJaKSVrJY2D1FZUY+vHlgABAKDwEAB0HND8\n"
"5kbxiJmqKIuuNqCJ2jHgs9G0xk4GdKvZEdq0JlRlc3QgVXNlciAyIDx0ZXN0dXNl\n"
"cjJAdGVzdC5nbnVwZy5vcmc+iHkEExMIACEFAle+4VYCGwMFCwkIBwIGFQgJCgsC\n"
"BBYCAwECHgECF4AACgkQRVRoUEJO+6zgFQD7BF3pnS3w3A7J9y+Y3kyGfmscXFWJ\n"
"Kme1PAsAlVSm1y4A+weReMvWFYHJH257v94yhStmV8egGoybsNDttNAW53cbnHwE\n"
"V77hVhIJKyQDAwIIAQEHAgMEX+6cF0HEn4g3ztFvwHyr7uwXMVYUGL3lE3mjhnV3\n"
"SbY6Dmy3OeFVnEVkawHqSv+HobpQTeEqNoQHAoIiXFCRlgMBCAcAAP9FykiyDspm\n"
"T33XWRPD+LAOmaIU7CIhfv9+lVkeExlU1w+qiGEEGBMIAAkFAle+4VYCGwwACgkQ\n"
"RVRoUEJO+6xjhgD/ZJ/MwYZJPk/xPYhTP8+wF+tErVNA8w3pP9D69dgUPdcA/izZ\n"
"Pji6YetVhgsyaHc4PrKynsk5G6nM3KkAOehUQsX8\n"
"=S/Wa\n"
"-----END PGP PRIVATE KEY BLOCK-----\n";

static const char *testResponse =
"From key-submission@test.gnupg.org Thu Aug 25 12:15:54 2016\n"
"Return-Path: <webkey@g10code.com>\n"
"From: key-submission@test.gnupg.org\n"
"To: testuser2@test.gnupg.org\n"
"Subject: Confirm your key publication\n"
"X-Wks-Loop: webkey.g10code.com\n"
"MIME-Version: 1.0\n"
"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";\n"
"	boundary=\"=-=01-wbu5fr9nu6fix5tcojjo=-=\"\n"
"Date: Thu, 25 Aug 2016 12:15:54 +0000\n"
"Message-Id: <E1bctZa-0004LE-Fr@kerckhoffs.g10code.com>\n"
"Sender:  <webkey@g10code.com>\n"
"X-Kolab-Scheduling-Message: FALSE\n"
"\n"
" \n"
"\n"
"--=-=01-wbu5fr9nu6fix5tcojjo=-=\n"
"Content-Type: application/pgp-encrypted\n"
"\n"
"Version: 1\n"
"\n"
"--=-=01-wbu5fr9nu6fix5tcojjo=-=\n"
"Content-Type: application/octet-stream\n"
"\n"
"-----BEGIN PGP MESSAGE-----\n"
"Version: GnuPG v2\n"
"\n"
"hH4D8pSp7hUsFUASAgMEg0w39E6d0TkFYxLbT6n3YcoKTT+Ur/c7Sn1ECyL7Rnuk\n"
"cmPO0adt3JxueK7Oz5COlk32SECFODdF3cQuDhkGxzC6Sfc4SfisdILmNhaT/MeW\n"
"8a+yE4skSK70absif4kw5XkvxXNxHeIHfAteP50jPJLSwEsBTEceb9cRMoP7s8w0\n"
"lYyi+RWQ7UKlKKywtcRCL4ow2H7spjx+a+3FzNOAoy7K0/thhLVRk8z+iuPi0/4n\n"
"Z2Ql60USLLUlfV2ZIpXdCd+5GjTJsnGhDos1pas5TZcOOAxO12Cg5TcqHISOaqa8\n"
"6BqxcKCU3NypIynOKHj375KArSs0WsEH8HWHyBBHB+NYtNpnTAuHNKxM+JtNxf+U\n"
"NfD2zptS6kyiHLw+4zjL5pEV7RHS2PBwWBDS6vhnyybNwckleya96U04iYiGRYGE\n"
"lUUR6Fl8H6x04dItFH1/jJA6Ppcu4FoYou04HADWCqJXPTgztjiW1/9QoCeXl5lm\n"
"CcOCcuw7lXp+qTejuns=\n"
"=SsWX\n"
"-----END PGP MESSAGE-----\n"
"\n"
"--=-=01-wbu5fr9nu6fix5tcojjo=-=--\n";


class WKSPublishTest : public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void testUnsupported()
    {
        // First check if it is supported
        auto job = openpgp()->wksPublishJob();
        connect(job, &WKSPublishJob::result, this,
                [this] (Error err, QByteArray, QByteArray, QString, Error) {
            QVERIFY(err);
            Q_EMIT asyncDone();
        });
        job->startCheck ("testuser1@localhost");
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }
#ifdef DO_ONLINE_TESTS
private Q_SLOTS:
#else
private:
#endif
    void testWSKPublishSupport()
    {
        // First check if it is supported
        auto job = openpgp()->wksPublishJob();
        connect(job, &WKSPublishJob::result, this,
                [this] (Error err, QByteArray, QByteArray, QString, Error) {
            if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.0.16") {
                std::cout << err;
                QVERIFY(err);
            } else {
                QVERIFY(!err);
            }
            Q_EMIT asyncDone();
        });
        job->startCheck ("testuser1@test.gnupg.org");
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

    void testWKSPublishErrors() {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.0.16") {
            /* Not supported */
            return;
        }
        auto job = openpgp()->wksPublishJob();
        connect(job, &WKSPublishJob::result, this,
                [this] (Error err, QByteArray, QByteArray, QString, Error) {
            QVERIFY(err);
            Q_EMIT asyncDone();
        });
        job->startCreate("AB874F24E98EBB8487EE7B170F8E3D97FE7011B7",
                         QStringLiteral("Foo@bar.baz"));
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

    void testWKSPublishCreate() {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.0.16") {
            /* Not supported */
            return;
        }
        /* First generate a test key */
        const QString args = QStringLiteral("<GnupgKeyParms format=\"internal\">\n"
                                        "%no-protection\n"
                                        "%transient-key\n"
                                        "key-type:      ECDSA\n"
                                        "key-curve:     brainpoolP256r1\n"
                                        "key-usage:     sign\n"
                                        "subkey-type:   ECDH\n"
                                        "subkey-curve:  brainpoolP256r1\n"
                                        "subkey-usage:  encrypt\n"
                                        "name-email:    %1\n"
                                        "name-real:     Test User\n"
                                        "</GnupgKeyParms>").arg(TEST_ADDRESS);

        auto keygenjob = openpgp()->keyGenerationJob();
        QByteArray fpr;
        connect(keygenjob, &KeyGenerationJob::result, this,
                [this, &fpr](KeyGenerationResult result, QByteArray, QString, Error)
        {
            QVERIFY(!result.error());
            fpr = QByteArray(result.fingerprint());
            QVERIFY(!fpr.isEmpty());
            Q_EMIT asyncDone();
        });
        keygenjob->start(args);
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        /* Then try to create a request. */
        auto job = openpgp()->wksPublishJob();
        connect(job, &WKSPublishJob::result, this,
                [this] (Error err, QByteArray out, QByteArray, QString, Error) {
            QVERIFY(!err);
            Q_EMIT asyncDone();
            const QString outstr = QString(out);
            QVERIFY(outstr.contains(
                     QStringLiteral("-----BEGIN PGP PUBLIC KEY BLOCK-----")));
            QVERIFY(outstr.contains(
                     QStringLiteral("Content-Type: application/pgp-keys")));
            QVERIFY(outstr.contains(
                     QStringLiteral("From: " TEST_ADDRESS)));
        });
        job->startCreate(fpr.constData(), QLatin1String(TEST_ADDRESS));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

    void testWKSPublishReceive() {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < "2.0.16") {
            /* Not supported */
            return;
        }
        auto importjob = openpgp()->importJob();
        connect(importjob, &ImportJob::result, this,
                [this](ImportResult result, QString, Error)
        {
            QVERIFY(!result.error());
            QVERIFY(!result.imports().empty());
            QVERIFY(result.numSecretKeysImported());
            Q_EMIT asyncDone();
        });
        importjob->start(QByteArray(testSecKey));
        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        /* Get a response. */
        auto job = openpgp()->wksPublishJob();
        connect(job, &WKSPublishJob::result, this,
                [this] (Error err, QByteArray out, QByteArray, QString, Error) {
            QVERIFY(!err);
            Q_EMIT asyncDone();
            const QString outstr = QString(out);
            QVERIFY(outstr.contains(
                     QStringLiteral("-----BEGIN PGP MESSAGE-----")));
            QVERIFY(outstr.contains(
                     QStringLiteral("Content-Type: multipart/encrypted;")));
            QVERIFY(outstr.contains(
                     QStringLiteral("From: " TEST_ADDRESS)));
        });
        job->startReceive(QByteArray(testResponse));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));
    }

    void initTestCase()
    {
        QGpgMETest::initTestCase();
        const QString gpgHome = qgetenv("GNUPGHOME");
        qputenv("GNUPGHOME", mDir.path().toUtf8());
        QVERIFY(mDir.isValid());
        QFile agentConf(mDir.path() + QStringLiteral("/gpg-agent.conf"));
        QVERIFY(agentConf.open(QIODevice::WriteOnly));
        agentConf.write("allow-loopback-pinentry");
        agentConf.close();
    }
private:
    QTemporaryDir mDir;
};

QTEST_MAIN(WKSPublishTest)

#include "t-wkspublish.moc"

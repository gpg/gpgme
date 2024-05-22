/* t-addexistingsubkey.cpp

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
#include "t-support.h"

#include "addexistingsubkeyjob.h"
#include "protocol.h"

#include <QSignalSpy>
#include <QTest>

#include <gpgme++/context.h>
#include <gpgme++/data.h>
#include <gpgme++/engineinfo.h>

#include <algorithm>

using namespace QGpgME;
using namespace GpgME;

static const char *requiredVersion = "2.3.5";

/* Test keys
    sec#  ed25519 2022-01-13 [SC]
        1CB8C6A0317AA83F44FE009932392C82B814C8E0
    uid           [ unknown] source-key@example.net
    ssb   cv25519 2022-01-13 [E]
    ssb   cv25519 2022-01-13 [E] [expires: 2100-01-01]

    sec   ed25519 2022-01-13 [SC]
        C3C87F0A3920B01F9E4450EA2B79F21D4DD10BFC
    uid           [ unknown] target-key@example.net
    ssb   cv25519 2022-01-13 [E]
 * generated with
export GNUPGHOME=$(mktemp -d)
gpg -K
gpg --batch --pinentry-mode loopback --passphrase abc --quick-gen-key source-key@example.net default default never
fpr=$(gpg -k --with-colons source-key@example.net | grep ^fpr | head -1 | cut -d ':' -f 10)
gpg --batch --pinentry-mode loopback --passphrase abc --quick-add-key ${fpr} default default 21000101T120000
gpg --batch --pinentry-mode loopback --passphrase abc --quick-gen-key target-key@example.net default default never
gpg -K
gpg --export-secret-subkeys --armor --batch --pinentry-mode loopback --passphrase abc --comment source-key@example.net source-key@example.net | sed 's/\(.*\)/    "\1\\n"/'
gpg --export-secret-keys --armor --batch --pinentry-mode loopback --passphrase abc --comment target-key@example.net target-key@example.net | sed 's/\(.*\)/    "\1\\n"/'
#rm -rf ${GNUPGHOME}
unset GNUPGHOME
*/
static const char *testKeyData =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    "Comment: source-key@example.net\n"
    "\n"
    "lDsEYd/ujBYJKwYBBAHaRw8BAQdAwiZPINTcrpgmu6ZWSaPZlcRSd4nDuofVMhe7\n"
    "c2XrFyT/AGUAR05VAbQWc291cmNlLWtleUBleGFtcGxlLm5ldIiUBBMWCgA8FiEE\n"
    "HLjGoDF6qD9E/gCZMjksgrgUyOAFAmHf7owCGwMFCwkIBwIDIgIBBhUKCQgLAgQW\n"
    "AgMBAh4HAheAAAoJEDI5LIK4FMjgupIA/Au2YEAT9dYdJd0eJCJerG5YAeoB+uBs\n"
    "mBkgr6xXE0bIAP43b6u1Jtvf/Wm3BhRbLd5Tg67Ba4CIZ8ZLGng73FBoBpyLBGHf\n"
    "7owSCisGAQQBl1UBBQEBB0Cpg8Qof/WShxROZZtmPnw24vTk0R8nIAF1CZJ0bG/C\n"
    "SwMBCAf+BwMCtzxziVxQEor8w/VVzHp4/hVSCUyrpiX7Djf04cIMs2bFPduZLgxb\n"
    "c1SXhlgiqU0YBNntbGGNdKjTP6FMbYWq1+NwQm6ZXtC76LPG7syM94h4BBgWCgAg\n"
    "FiEEHLjGoDF6qD9E/gCZMjksgrgUyOAFAmHf7owCGwwACgkQMjksgrgUyOCI0wEA\n"
    "+f56fkvDDUwMOMw7n4+GKpfJXpWhVL08ttccbBOa/9IA/2HYA/78ZaD8E5EyqAEK\n"
    "Aj9Au+2oJu9V5qo92QEoqwYHnIsEYd/vgxIKKwYBBAGXVQEFAQEHQBa9FxJkm/9D\n"
    "xABildkaYMrbJbu8BPk6uv9V8aLmv9FnAwEIB/4HAwIPhcbN8s6OzPz8/g78TrCh\n"
    "xqQb2kygCEj+OQ4/XXU3lus2b5xS5h44LGt99Wisqx+wVPDXmPDJOaxjhHXDmJxd\n"
    "/LplIEhykojSm3uUDxERiH4EGBYKACYWIQQcuMagMXqoP0T+AJkyOSyCuBTI4AUC\n"
    "Yd/vgwIbDAUJkqcQPQAKCRAyOSyCuBTI4IUjAP9BTfOD+jy6lLmzNO9pquRSAxi/\n"
    "PQuglGtpS0LQEJMEOwD+PFnsMe2EtQ+WVSDBeB7O0m61EXeY+RhpuhNtsNXVuwc=\n"
    "=wIPU\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n"
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
    "Comment: target-key@example.net\n"
    "\n"
    "lIYEYd/v/RYJKwYBBAHaRw8BAQdAKoILWXG3yaLb2EniNKQLUjwsrvy5vgAN299J\n"
    "W5cFbrz+BwMC/uKbCq3sK5H8QVtEQ/IxGmjWNBpy6c8EDlOG4APi4o4VE+bEYD8w\n"
    "J3Kk/lzSm6ZT5vC6DDASks797omjXD+J7zZ0vtTPvheYi/nsVz2UebQWdGFyZ2V0\n"
    "LWtleUBleGFtcGxlLm5ldIiUBBMWCgA8FiEEw8h/CjkgsB+eRFDqK3nyHU3RC/wF\n"
    "AmHf7/0CGwMFCwkIBwIDIgIBBhUKCQgLAgQWAgMBAh4HAheAAAoJECt58h1N0Qv8\n"
    "rXcBAPxnkXqpp4IY3iTKV5XAdo7Uys7U/joUD73rj2XEvgI1AQDhKK4PLxPhf3ki\n"
    "FKU0RA7itxzOH+F8bQ5BdYS49jDPCpyLBGHf7/0SCisGAQQBl1UBBQEBB0Dq9rwA\n"
    "hAA2UFJShFsLFp7+g4uhWDfuDa3VjeIQRM+9QgMBCAf+BwMCMfCTl0LNqsn836t5\n"
    "f2ZHBuMcNs4JWYmdLAIVaewEHq7zhOsX3iB+/yxwu9g2mXc4XUJ1iQzXLOYwgGov\n"
    "8jIovrr01hDkSg4rvM9JKMWdd4h4BBgWCgAgFiEEw8h/CjkgsB+eRFDqK3nyHU3R\n"
    "C/wFAmHf7/0CGwwACgkQK3nyHU3RC/xyfAEAqnMdSv6FTAwAWrYvJqJtSVoEhjMn\n"
    "3c2qMsu34Bk86/MBAKHbLFmdyePvHaxKeO8CkQDoJzK8rYzw3RAmq/5JsQkL\n"
    "=rOVf\n"
    "-----END PGP PRIVATE KEY BLOCK-----\n";

class AddExistingSubkeyJobTest : public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:

    void initTestCase()
    {
        QGpgMETest::initTestCase();

        // set up the test fixture for this test
        qputenv("GNUPGHOME", mGnupgHomeTestFixture.path().toUtf8());
        QVERIFY(importSecretKeys(testKeyData, 2));
    }

    void init()
    {
        if (GpgME::engineInfo(GpgME::GpgEngine).engineVersion() < requiredVersion) {
            QSKIP("gpg does not yet support adding an existing subkey to another key via the command API");
        }

        // set up a copy of the test fixture for each test function
        mGnupgHomeTestCopy.reset(new QTemporaryDir{});
        QVERIFY(copyKeyrings(mGnupgHomeTestFixture.path(), mGnupgHomeTestCopy->path()));
        qputenv("GNUPGHOME", mGnupgHomeTestCopy->path().toUtf8());
    }

    void testAddExistingSubkeyAsync()
    {
        // Get the key the subkey should be added to
        auto key = getTestKey("target-key@example.net");
        QVERIFY(!key.isNull());

        // Get the key with the subkey to add
        auto sourceKey = getTestKey("source-key@example.net", 3);
        QVERIFY(!sourceKey.isNull());

        auto job = std::unique_ptr<AddExistingSubkeyJob>{openpgp()->addExistingSubkeyJob()};
        hookUpPassphraseProvider(job.get());

        Error result;
        connect(job.get(), &AddExistingSubkeyJob::result,
                job.get(), [this, &result](const Error &result_) {
                    result = result_;
                    Q_EMIT asyncDone();
                });
        QVERIFY(!job->start(key, sourceKey.subkey(1)));
        job.release(); // after the job has been started it's on its own

        QSignalSpy spy (this, SIGNAL(asyncDone()));
        QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

        QCOMPARE(result.code(), static_cast<int>(GPG_ERR_NO_ERROR));
        key.update();
        QCOMPARE(key.numSubkeys(), 3u);
    }

    void testAddExistingSubkeySync()
    {
        // Get the key the subkey should be added to
        auto key = getTestKey("target-key@example.net");
        QVERIFY(!key.isNull());

        // Get the key with the subkey to add
        auto sourceKey = getTestKey("source-key@example.net", 3);
        QVERIFY(!sourceKey.isNull());
        auto sourceSubkey = sourceKey.subkey(1);
        QVERIFY(sourceSubkey.expirationTime() == 0);

        auto job = std::unique_ptr<AddExistingSubkeyJob>{openpgp()->addExistingSubkeyJob()};
        hookUpPassphraseProvider(job.get());

        const auto result = job->exec(key, sourceSubkey);

        QCOMPARE(result.code(), static_cast<int>(GPG_ERR_NO_ERROR));
        key.update();
        QCOMPARE(key.numSubkeys(), 3u);
        QCOMPARE(key.subkey(2).expirationTime(), 0);
    }

    void testAddExistingSubkeyWithExpiration()
    {
        // Get the key the subkey should be added to
        auto key = getTestKey("target-key@example.net");
        QVERIFY(!key.isNull());

        // Get the key with the subkey to add
        auto sourceKey = getTestKey("source-key@example.net", 3);
        QVERIFY(!sourceKey.isNull());
        auto sourceSubkey = sourceKey.subkey(2);
        QVERIFY(sourceSubkey.expirationTime() != 0);

        auto job = std::unique_ptr<AddExistingSubkeyJob>{openpgp()->addExistingSubkeyJob()};
        hookUpPassphraseProvider(job.get());

        const auto result = job->exec(key, sourceSubkey);

        if (sourceSubkey.expirationTime() > 0) {
            QCOMPARE(result.code(), static_cast<int>(GPG_ERR_NO_ERROR));
            key.update();
            QCOMPARE(key.numSubkeys(), 3u);

            // allow 1 second different expiration because gpg calculates with
            // expiration as difference to current time and takes current time
            // several times
            const auto allowedDeltaTSeconds = 1;
            const auto expectedExpirationRange = std::make_pair(
                uint_least32_t(sourceSubkey.expirationTime()) - allowedDeltaTSeconds,
                uint_least32_t(sourceSubkey.expirationTime()) + allowedDeltaTSeconds);
            const auto actualExpiration = uint_least32_t(key.subkey(2).expirationTime());
            QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                    ("actual: " + std::to_string(actualExpiration) +
                    "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
            QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                    ("actual: " + std::to_string(actualExpiration) +
                    "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
        } else {
            // on 32-bit systems the expiration date of the test key overflows;
            // in this case we expect an appropriate error code
            QCOMPARE(result.code(), static_cast<int>(GPG_ERR_INV_TIME));
        }
    }

private:
    Key getTestKey(const char *pattern, unsigned int expectedSubkeys = 2)
    {
        auto ctx = Context::create(OpenPGP);
        VERIFY_OR_OBJECT(ctx);

        Error err;
        auto key = ctx->key(pattern, err, /*secret=*/true);
        VERIFY_OR_OBJECT(!err);
        VERIFY_OR_OBJECT(!key.isNull());
        COMPARE_OR_OBJECT(key.numSubkeys(), expectedSubkeys);
        for (unsigned int i = 0; i < key.numSubkeys(); ++i) {
            VERIFY_OR_OBJECT(!key.subkey(i).isNull());
        }
        return key;
    }

private:
    QTemporaryDir mGnupgHomeTestFixture;
    std::unique_ptr<QTemporaryDir> mGnupgHomeTestCopy;
};

QTEST_MAIN(AddExistingSubkeyJobTest)

#include "t-addexistingsubkey.moc"

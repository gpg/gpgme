/* t-verifiy.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2016 by Bundesamt für Sicherheit in der Informationstechnik
    Software engineering by Intevation GmbH
    Copyright (c) 2023 by g10 Code GmbH
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

#include <protocol.h>
#include <decryptverifyjob.h>

#include <QDebug>
#include <QTest>

#include <decryptionresult.h>
#include <key.h>
#include <verificationresult.h>

using namespace QGpgME;
using namespace GpgME;

static const char encryptedText[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"jA0ECQMCnJt+DX+RJJH90kIBCYlu/LYn57TCNO+O8kYwe4jcyEIaHqSZuvO50nFE\n"
"hQy9p33Y5VwP6uDOYOKxr1W6iE4GvbX+5UNKYdjjPL0m1ak=\n"
"=hgKY\n"
"-----END PGP MESSAGE-----\n";

static const char signedText[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"owGbwMvMwCSoW1RzPCOz3IRxjXQSR0lqcYleSUWJTZOvjVdpcYmCu1+oQmaJIleH\n"
"GwuDIBMDGysTSIqBi1MApi+nlGGuwDeHao53HBr+FoVGP3xX+kvuu9fCMJvl6IOf\n"
"y1kvP4y+8D5a11ang0udywsA\n"
"=Crq6\n"
"-----END PGP MESSAGE-----\n";

static const char storedText[] =
"-----BEGIN PGP MESSAGE-----\n"
"\n"
"owE7LZzEkHy7X86rtLhEwd0vVCGzRJELAA==\n"
"=VwL6\n"
"-----END PGP MESSAGE-----\n";

class DecryptVerifyTest: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:

    void testEncryptedOnlyData()
    {
        const QByteArray encryptedData{encryptedText};
        std::unique_ptr<DecryptVerifyJob> job{openpgp()->decryptVerifyJob(true)};
        hookUpPassphraseProvider(job.get());

        QByteArray verified;
        const auto result = job->exec(encryptedData, verified);

        const auto decryptionResult = result.first;
        QCOMPARE(decryptionResult.error().code(), int{GPG_ERR_NO_ERROR});
        const auto verificationResult = result.second;
        QCOMPARE(verificationResult.error().code(), int{GPG_ERR_NO_ERROR});
        QCOMPARE(verificationResult.numSignatures(), 0u);
    }

    void testSignedOnlyData()
    {
        const QByteArray signedData{signedText};
        std::unique_ptr<DecryptVerifyJob> job{openpgp()->decryptVerifyJob(true)};

        QByteArray verified;
        const auto result = job->exec(signedData, verified);

        const auto decryptionResult = result.first;
        QCOMPARE(decryptionResult.error().code(), int{GPG_ERR_NO_DATA});
        const auto verificationResult = result.second;
        QCOMPARE(verificationResult.error().code(), int{GPG_ERR_NO_ERROR});
        QCOMPARE(verificationResult.numSignatures(), 1u);
    }

    void testStoredData()
    {
        const QByteArray storedData{storedText};
        std::unique_ptr<DecryptVerifyJob> job{openpgp()->decryptVerifyJob(true)};

        QByteArray verified;
        const auto result = job->exec(storedData, verified);

        const auto decryptionResult = result.first;
        QCOMPARE(decryptionResult.error().code(), int{GPG_ERR_NO_DATA});
        const auto verificationResult = result.second;
        QCOMPARE(verificationResult.error().code(), int{GPG_ERR_NO_DATA});
        QCOMPARE(verificationResult.numSignatures(), 0u);
    }
};

QTEST_MAIN(DecryptVerifyTest)
#include "t-decryptverify.moc"

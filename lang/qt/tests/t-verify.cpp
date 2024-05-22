/* t-verifiy.cpp

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


#include "protocol.h"

#include "verifyopaquejob.h"
#include <gpgme++/verificationresult.h>
#include <gpgme++/key.h>

#include "t-support.h"

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


class VerifyTest: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:

    /* Check that a signature always has a key. */
    void testSignatureKey()
    {
        const QByteArray signedData(testMsg1);
        auto verifyJob = openpgp()->verifyOpaqueJob(true);
        QByteArray verified;

        auto result = verifyJob->exec(signedData, verified);
        QVERIFY(!result.error());
        delete verifyJob;

        QVERIFY(result.numSignatures() == 1);
        auto sig = result.signatures()[0];

        const auto key = sig.key(true, false);
        QVERIFY(!key.isNull());

        bool found = false;
        for (const auto &subkey: key.subkeys()) {
            if (!strcmp (subkey.fingerprint(), sig.fingerprint())) {
                found = true;
            }
        }
        QVERIFY(found);
    }
};

QTEST_MAIN(VerifyTest)
#include "t-verify.moc"

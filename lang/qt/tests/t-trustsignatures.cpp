/* t-trustsignatures.cpp

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2021 g10 Code GmbH
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

#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include "protocol.h"
#include "signkeyjob.h"

#include <QRegularExpression>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace QGpgME;
using namespace GpgME;

class TestTrustSignatures: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void test_tsign_single_uid_key_and_then_tsign_it_again()
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

        // Get the target key (victor@example.org)
        auto target = ctx->key("E8143C489C8D41124DC40D0B47AF4B6961F04784", err, false);
        QVERIFY(!err);
        QVERIFY(!target.isNull());
        QVERIFY(target.numUserIDs() > 0);

        // Create first trust signature
        {
            // Create the job
            auto job = std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setTrustSignature(TrustSignatureTrust::Complete, 1, QStringLiteral("example.org"));

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
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 1u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Complete);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.org>")).hasMatch());
        }

        // Create second trust signature
        {
            // Create the job
            auto job = std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setDupeOk(true);
            job->setTrustSignature(TrustSignatureTrust::Partial, 2, QStringLiteral("example.net"));

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

            err = job->start(target);
            QVERIFY(!err);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 2u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Partial);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.net>")).hasMatch());
        }
    }

    void test_tsign_multi_uid_key_and_then_tsign_it_again()
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

        // Create first trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setTrustSignature(TrustSignatureTrust::Complete, 1, QStringLiteral("example.org"));

            connect(job, &SignKeyJob::result,
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
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 1u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Complete);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.org>")).hasMatch());
        }

        // Create second trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setDupeOk(true);
            job->setTrustSignature(TrustSignatureTrust::Partial, 2, QStringLiteral("example.net"));

            connect(job, &SignKeyJob::result,
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

            err = job->start(target);
            QVERIFY(!err);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 2u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Partial);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.net>")).hasMatch());
        }
    }

    void test_tsign_first_uid_and_then_tsign_both_uids()
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

        // Get the target key (Mallory / Mike Test)
        auto target = ctx->key("2686AA191A278013992C72EBBE794852BE5CF886", err, false);
        QVERIFY(!err);
        QVERIFY(!target.isNull());
        QVERIFY(target.numUserIDs() > 0);

        // Create first trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setUserIDsToSign({0});
            job->setTrustSignature(TrustSignatureTrust::Complete, 1, QStringLiteral("example.org"));

            connect(job, &SignKeyJob::result,
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
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 1u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Complete);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.org>")).hasMatch());
        }

        // Create second trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setDupeOk(true);
            job->setTrustSignature(TrustSignatureTrust::Partial, 2, QStringLiteral("example.net"));

            connect(job, &SignKeyJob::result,
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

            err = job->start(target);
            QVERIFY(!err);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 2u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Partial);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.net>")).hasMatch());
        }
    }

    void test_tsign_all_uids_and_then_tsign_first_uid()
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

        // Get the target key (Echelon / Echo Test / Eve)
        auto target = ctx->key("3531152DE293E26A07F504BC318C1FAEFAEF6D1B", err, false);
        QVERIFY(!err);
        QVERIFY(!target.isNull());
        QVERIFY(target.numUserIDs() > 0);

        // Create first trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setTrustSignature(TrustSignatureTrust::Complete, 1, QStringLiteral("example.org"));

            connect(job, &SignKeyJob::result,
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
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 1u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Complete);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.org>")).hasMatch());
        }

        // Create second trust signature
        {
            // Create the job
            auto job = openpgp()->signKeyJob();//std::unique_ptr<SignKeyJob>{openpgp()->signKeyJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job);

            // Set up the job
            job->setExportable(true);
            job->setSigningKey(seckey);
            job->setUserIDsToSign({0});
            job->setDupeOk(true);
            job->setTrustSignature(TrustSignatureTrust::Partial, 2, QStringLiteral("example.net"));

            connect(job, &SignKeyJob::result,
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

            err = job->start(target);
            QVERIFY(!err);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the trust signature should have been added.
            target.update();
            const auto trustSignature = target.userID(0).signature(target.userID(0).numSignatures() - 1);
            QVERIFY(trustSignature.isTrustSignature());
            QCOMPARE(trustSignature.trustDepth(), 2u);
            QCOMPARE(trustSignature.trustValue(), TrustSignatureTrust::Partial);
            QVERIFY(trustSignature.trustScope());
            const auto trustScope = QString::fromUtf8(trustSignature.trustScope());
            QVERIFY(!trustScope.isEmpty());
            const QRegularExpression regex{trustScope};
            QVERIFY(regex.isValid());
            QVERIFY(regex.match(QStringLiteral("Foo <foo@example.net>")).hasMatch());
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
            conf.write("allow-weak-key-signatures");
        }
        conf.close();
    }

private:
    QTemporaryDir mDir;
};

QTEST_MAIN(TestTrustSignatures)

#include "t-trustsignatures.moc"

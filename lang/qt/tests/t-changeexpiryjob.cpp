/* t-changeexpiryjob.cpp

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

#include "t-support.h"

#include "changeexpiryjob.h"
#include <gpgme++/context.h>
#include <gpgme++/engineinfo.h>
#include "protocol.h"

#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>

using namespace QGpgME;
using namespace GpgME;

class TestChangeExpiryJob: public QGpgMETest
{
    Q_OBJECT

private Q_SLOTS:
    void test_change_expiration_default_without_subkeys()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the key (alfa@example.net)
        auto key = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!key.isNull());
        QVERIFY(!key.subkey(0).isNull());
        QVERIFY(!key.subkey(1).isNull());
        const auto subkeyExpiration = uint_least32_t(key.subkey(1).expirationTime());

        {
            // Create the job
            auto job = std::unique_ptr<ChangeExpiryJob>{openpgp()->changeExpiryJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Use defaults of job

            connect(job.get(), &ChangeExpiryJob::result,
                    this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                        Q_EMIT asyncDone();
                        if (err2) {
                            QFAIL(qPrintable(QString("The ChangeExpiryJob failed with '%1'.").arg(err2.asString())));
                        }
                    });

            const auto newExpirationDate = QDateTime::currentDateTime().addDays(1);
            job->start(key, newExpirationDate);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the expiration date should have been changed.
            key.update();

            // allow a few seconds earlier expiration because job calculates "seconds from now" passed to gpg after it was started
            const auto expectedExpirationRange = std::make_pair(
                newExpirationDate.toSecsSinceEpoch() - 10,
                QDateTime::currentDateTime().addDays(1).toSecsSinceEpoch());
            {
                const auto actualExpiration = uint_least32_t(key.subkey(0).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
            {
                const auto actualExpiration = uint_least32_t(key.subkey(1).expirationTime());
                QCOMPARE(actualExpiration, subkeyExpiration);  // unchanged
            }
        }
    }

    void test_change_expiration_default_with_subkeys()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the key (alfa@example.net)
        auto key = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!key.isNull());
        QVERIFY(!key.subkey(0).isNull());
        QVERIFY(!key.subkey(1).isNull());
        const auto primaryKeyExpiration = uint_least32_t(key.subkey(0).expirationTime());

        {
            // Create the job
            auto job = std::unique_ptr<ChangeExpiryJob>{openpgp()->changeExpiryJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Use defaults of job

            connect(job.get(), &ChangeExpiryJob::result,
                    this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                        Q_EMIT asyncDone();
                        if (err2) {
                            QFAIL(qPrintable(QString("The ChangeExpiryJob failed with '%1'.").arg(err2.asString())));
                        }
                    });

            const auto newExpirationDate = QDateTime::currentDateTime().addDays(2);
            job->start(key, newExpirationDate, {key.subkey(1)});
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the expiration date should have been changed.
            key.update();

            // allow a few seconds earlier expiration because job calculates "seconds from now" passed to gpg after it was started
            const auto expectedExpirationRange = std::make_pair(
                newExpirationDate.toSecsSinceEpoch() - 10,
                QDateTime::currentDateTime().addDays(2).toSecsSinceEpoch());
            {
                const auto actualExpiration = uint_least32_t(key.subkey(0).expirationTime());
                QCOMPARE(actualExpiration, primaryKeyExpiration);  // unchanged
            }
            {
                const auto actualExpiration = uint_least32_t(key.subkey(1).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
        }
    }

    void test_change_expiration_update_primary_key_without_subkeys()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the key (alfa@example.net)
        auto key = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!key.isNull());
        QVERIFY(!key.subkey(0).isNull());
        QVERIFY(!key.subkey(1).isNull());
        const auto subkeyExpiration = uint_least32_t(key.subkey(1).expirationTime());

        {
            // Create the job
            auto job = std::unique_ptr<ChangeExpiryJob>{openpgp()->changeExpiryJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Set up the job
            job->setOptions(ChangeExpiryJob::UpdatePrimaryKey);

            connect(job.get(), &ChangeExpiryJob::result,
                    this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                        Q_EMIT asyncDone();
                        if (err2) {
                            QFAIL(qPrintable(QString("The ChangeExpiryJob failed with '%1'.").arg(err2.asString())));
                        }
                    });

            const auto newExpirationDate = QDateTime::currentDateTime().addDays(3);
            job->start(key, newExpirationDate, {});
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the expiration date should have been changed.
            key.update();

            // allow a few seconds earlier expiration because job calculates "seconds from now" passed to gpg after it was started
            const auto expectedExpirationRange = std::make_pair(
                newExpirationDate.toSecsSinceEpoch() - 10,
                QDateTime::currentDateTime().addDays(3).toSecsSinceEpoch());
            {
                const auto actualExpiration = uint_least32_t(key.subkey(0).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
            {
                const auto actualExpiration = uint_least32_t(key.subkey(1).expirationTime());
                QCOMPARE(actualExpiration, subkeyExpiration);  // unchanged
            }
        }
    }

    void test_change_expiration_update_primary_key_with_subkeys()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the key (alfa@example.net)
        auto key = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!key.isNull());
        QVERIFY(!key.subkey(0).isNull());
        QVERIFY(!key.subkey(1).isNull());

        {
            // Create the job
            auto job = std::unique_ptr<ChangeExpiryJob>{openpgp()->changeExpiryJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Set up the job
            job->setOptions(ChangeExpiryJob::UpdatePrimaryKey);

            connect(job.get(), &ChangeExpiryJob::result,
                    this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                        Q_EMIT asyncDone();
                        if (err2) {
                            QFAIL(qPrintable(QString("The ChangeExpiryJob failed with '%1'.").arg(err2.asString())));
                        }
                    });

            const auto newExpirationDate = QDateTime::currentDateTime().addDays(4);
            job->start(key, newExpirationDate, {key.subkey(1)});
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the expiration date should have been changed.
            key.update();

            // allow a few seconds earlier expiration because job calculates "seconds from now" passed to gpg after it was started
            const auto expectedExpirationRange = std::make_pair(
                newExpirationDate.toSecsSinceEpoch() - 10,
                QDateTime::currentDateTime().addDays(4).toSecsSinceEpoch());
            {
                const auto actualExpiration = uint_least32_t(key.subkey(0).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
            {
                const auto actualExpiration = uint_least32_t(key.subkey(1).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                          "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                          "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
        }
    }

    void test_change_expiration_update_primary_key_and_all_subkeys()
    {
        Error err;

        if (!loopbackSupported()) {
            return;
        }

        auto ctx = Context::create(OpenPGP);
        QVERIFY(ctx);

        // Get the key (alfa@example.net)
        auto key = ctx->key("A0FF4590BB6122EDEF6E3C542D727CC768697734", err, true);
        QVERIFY(!err);
        QVERIFY(!key.isNull());
        QVERIFY(!key.subkey(0).isNull());
        QVERIFY(!key.subkey(1).isNull());

        {
            // Create the job
            auto job = std::unique_ptr<ChangeExpiryJob>{openpgp()->changeExpiryJob()};
            QVERIFY(job);
            hookUpPassphraseProvider(job.get());

            // Set up the job
            job->setOptions(ChangeExpiryJob::UpdatePrimaryKey | ChangeExpiryJob::UpdateAllSubkeys);

            connect(job.get(), &ChangeExpiryJob::result,
                    this, [this] (const GpgME::Error &err2, const QString &, const GpgME::Error &) {
                        Q_EMIT asyncDone();
                        if (err2) {
                            QFAIL(qPrintable(QString("The ChangeExpiryJob failed with '%1'.").arg(err2.asString())));
                        }
                    });

            const auto newExpirationDate = QDateTime::currentDateTime().addDays(5);
            job->start(key, newExpirationDate);
            QSignalSpy spy (this, SIGNAL(asyncDone()));
            QVERIFY(spy.wait(QSIGNALSPY_TIMEOUT));

            // At this point the expiration date should have been changed.
            key.update();

            // allow a few seconds earlier expiration because job calculates "seconds from now" passed to gpg after it was started
            const auto expectedExpirationRange = std::make_pair(
                newExpirationDate.toSecsSinceEpoch() - 10,
                QDateTime::currentDateTime().addDays(5).toSecsSinceEpoch());
            {
                const auto actualExpiration = uint_least32_t(key.subkey(0).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                         "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
            {
                const auto actualExpiration = uint_least32_t(key.subkey(1).expirationTime());
                QVERIFY2(actualExpiration >= expectedExpirationRange.first,
                        ("actual: " + std::to_string(actualExpiration) +
                          "; expected: " + std::to_string(expectedExpirationRange.first)).c_str());
                QVERIFY2(actualExpiration <= expectedExpirationRange.second,
                        ("actual: " + std::to_string(actualExpiration) +
                          "; expected: " + std::to_string(expectedExpirationRange.second)).c_str());
            }
        }
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

QTEST_MAIN(TestChangeExpiryJob)

#include "t-changeexpiryjob.moc"

/*
    threadedjobmixin.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2008 Klarälvdalens Datakonsult AB
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

#ifndef __QGPGME_THREADEDJOBMIXING_H__
#define __QGPGME_THREADEDJOBMIXING_H__

#include <QMutex>
#include <QMutexLocker>
#include <QThread>
#include <QString>
#include <QIODevice>

#ifdef BUILDING_QGPGME
# include "context.h"
# include "interfaces/progressprovider.h"
#else
# include <gpgme++/context.h>
# include <gpgme++/interfaces/progressprovider.h>
#endif

#include "job.h"

#include <cassert>
#include <functional>

namespace QGpgME
{
namespace _detail
{

QString audit_log_as_html(GpgME::Context *ctx, GpgME::Error &err);

class PatternConverter
{
    const QList<QByteArray> m_list;
    mutable const char **m_patterns;
public:
    explicit PatternConverter(const QByteArray &ba);
    explicit PatternConverter(const QString &s);
    explicit PatternConverter(const QList<QByteArray> &lba);
    explicit PatternConverter(const QStringList &sl);
    ~PatternConverter();

    const char **patterns() const;
};

class ToThreadMover
{
    QObject *const m_object;
    QThread *const m_thread;
public:
    ToThreadMover(QObject *o, QThread *t) : m_object(o), m_thread(t) {}
    ToThreadMover(QObject &o, QThread *t) : m_object(&o), m_thread(t) {}
    ToThreadMover(const std::shared_ptr<QObject> &o, QThread *t) : m_object(o.get()), m_thread(t) {}
    ~ToThreadMover()
    {
        if (m_object && m_thread) {
            m_object->moveToThread(m_thread);
        }
    }
};

template <typename T_result>
class Thread : public QThread
{
public:
    explicit Thread(QObject *parent = nullptr) : QThread(parent) {}

    void setFunction(const std::function<T_result()> &function)
    {
        const QMutexLocker locker(&m_mutex);
        m_function = function;
    }

    bool hasFunction()
    {
        const QMutexLocker locker(&m_mutex);
        return static_cast<bool>(m_function);
    }

    T_result result() const
    {
        const QMutexLocker locker(&m_mutex);
        return m_result;
    }

private:
    void run() override {
        const QMutexLocker locker(&m_mutex);
        m_result = m_function();
    }
private:
    mutable QMutex m_mutex;
    std::function<T_result()> m_function;
    T_result m_result;
};

template <typename T_base, typename T_result = std::tuple<GpgME::Error, QString, GpgME::Error> >
class ThreadedJobMixin : public T_base, public GpgME::ProgressProvider
{
public:
    typedef ThreadedJobMixin<T_base, T_result> mixin_type;
    typedef T_result result_type;

    void run()
    {
        Q_ASSERT(m_thread.hasFunction() && "Call setWorkerFunction() before run()");
        m_thread.start();
    }

protected:
    static_assert(std::tuple_size<T_result>::value > 2,
                  "Result tuple too small");
    static_assert(std::is_same <
                  typename std::tuple_element <
                  std::tuple_size<T_result>::value - 2,
                  T_result
                  >::type,
                  QString
                  >::value,
                  "Second to last result type not a QString");
    static_assert(std::is_same <
                  typename std::tuple_element <
                  std::tuple_size<T_result>::value - 1,
                  T_result
                  >::type,
                  GpgME::Error
                  >::value,
                  "Last result type not a GpgME::Error");

    explicit ThreadedJobMixin(GpgME::Context *ctx)
        : T_base(nullptr), m_ctx(ctx), m_thread(), m_auditLog(), m_auditLogError()
    {
    }

    void lateInitialization()
    {
        assert(m_ctx);
        QObject::connect(&m_thread, &QThread::finished, this,
                         &mixin_type::slotFinished);
        m_ctx->setProgressProvider(this);
        QGpgME::g_context_map.insert(this, m_ctx.get());
    }

    ~ThreadedJobMixin()
    {
        QGpgME::g_context_map.remove(this);
    }

    template <typename T_binder>
    void setWorkerFunction(const T_binder &func)
    {
        m_thread.setFunction([this, func]() { return func(this->context()); });
    }

public:
    template <typename T_binder>
    void run(const T_binder &func)
    {
        m_thread.setFunction(std::bind(func, this->context()));
        m_thread.start();
    }
    template <typename T_binder>
    void run(const T_binder &func, const std::shared_ptr<QIODevice> &io)
    {
        if (io) {
            io->moveToThread(&m_thread);
        }
        // the arguments passed here to the functor are stored in a QThread, and are not
        // necessarily destroyed (living outside the UI thread) at the time the result signal
        // is emitted and the signal receiver wants to clean up IO devices.
        // To avoid such races, we pass std::weak_ptr's to the functor.
        m_thread.setFunction(std::bind(func, this->context(), this->thread(), std::weak_ptr<QIODevice>(io)));
        m_thread.start();
    }
    template <typename T_binder>
    void run(const T_binder &func, const std::shared_ptr<QIODevice> &io1, const std::shared_ptr<QIODevice> &io2)
    {
        if (io1) {
            io1->moveToThread(&m_thread);
        }
        if (io2) {
            io2->moveToThread(&m_thread);
        }
        // the arguments passed here to the functor are stored in a QThread, and are not
        // necessarily destroyed (living outside the UI thread) at the time the result signal
        // is emitted and the signal receiver wants to clean up IO devices.
        // To avoid such races, we pass std::weak_ptr's to the functor.
        m_thread.setFunction(std::bind(func, this->context(), this->thread(), std::weak_ptr<QIODevice>(io1), std::weak_ptr<QIODevice>(io2)));
        m_thread.start();
    }

protected:
    GpgME::Context *context() const
    {
        return m_ctx.get();
    }

    virtual void resultHook(const result_type &) {}

    void slotFinished()
    {
        const T_result r = m_thread.result();
        m_auditLog = std::get < std::tuple_size<T_result>::value - 2 > (r);
        m_auditLogError = std::get < std::tuple_size<T_result>::value - 1 > (r);
        resultHook(r);
        Q_EMIT this->done();
        doEmitResult(r);
        this->deleteLater();
    }
    void slotCancel() override {
        if (m_ctx)
        {
            m_ctx->cancelPendingOperation();
        }
    }
    QString auditLogAsHtml() const override
    {
        return m_auditLog;
    }
    GpgME::Error auditLogError() const override
    {
        return m_auditLogError;
    }
    void showProgress(const char *what,
                      int type, int current, int total) override {
        QMetaObject::invokeMethod(this, [this, current, total]() {
            Q_EMIT this->jobProgress(current, total);
        }, Qt::QueuedConnection);
        const QString what_ = QString::fromUtf8(what);
        QMetaObject::invokeMethod(this, [this, what_, type, current, total]() {
            Q_EMIT this->rawProgress(what_, type, current, total);
        }, Qt::QueuedConnection);
        QMetaObject::invokeMethod(this, [this, what_, current, total]() {
            QT_WARNING_PUSH
            QT_WARNING_DISABLE_DEPRECATED
            Q_EMIT this->progress(what_, current, total);
            QT_WARNING_POP
        }, Qt::QueuedConnection);
    }
private:
    template <typename T1, typename T2>
    void doEmitResult(const std::tuple<T1, T2> &tuple)
    {
        Q_EMIT this->result(std::get<0>(tuple), std::get<1>(tuple));
    }

    template <typename T1, typename T2, typename T3>
    void doEmitResult(const std::tuple<T1, T2, T3> &tuple)
    {
        Q_EMIT this->result(std::get<0>(tuple), std::get<1>(tuple), std::get<2>(tuple));
    }

    template <typename T1, typename T2, typename T3, typename T4>
    void doEmitResult(const std::tuple<T1, T2, T3, T4> &tuple)
    {
        Q_EMIT this->result(std::get<0>(tuple), std::get<1>(tuple), std::get<2>(tuple), std::get<3>(tuple));
    }

    template <typename T1, typename T2, typename T3, typename T4, typename T5>
    void doEmitResult(const std::tuple<T1, T2, T3, T4, T5> &tuple)
    {
        Q_EMIT this->result(std::get<0>(tuple), std::get<1>(tuple), std::get<2>(tuple), std::get<3>(tuple), std::get<4>(tuple));
    }

private:
    std::shared_ptr<GpgME::Context> m_ctx;
    Thread<T_result> m_thread;
    QString m_auditLog;
    GpgME::Error m_auditLogError;
};

}
}

#endif /* __QGPGME_THREADEDJOBMIXING_H__ */

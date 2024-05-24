/*
    job.h

    This file is part of qgpgme, the Qt API binding for gpgme
    Copyright (c) 2004 Klarälvdalens Datakonsult AB
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

#ifndef __KLEO_JOB_H__
#define __KLEO_JOB_H__

#include "qgpgme_export.h"

#include <QObject>
#include <QString>
#include <QMap>

#include <gpgme++/error.h>

class QWidget;

namespace QGpgME
{

/**
   @short An abstract base class for asynchronous crypto operations

   During the operation, you might receive progress updates through
   the progress() signal as they arrive, but an implementation is
   free to not send progress information. You should show a busy
   progressbar until the first progress() signal is received.

   The done() signal is emitted _before_ the result() signals of
   subclasses and should be used to hide and/or reset progress bars,
   not to learn of the end of the operation. Use the result()
   signals for that.

   To cancel the operation, simply call slotCancel(). The result()
   signal of subclasses will still be emitted, though, and will
   carry the information that the operation was canceled.
*/
class QGPGME_EXPORT Job : public QObject
{
    Q_OBJECT
protected:
    explicit Job(QObject *parent);
public:
    ~Job();

    virtual QString auditLogAsHtml() const;
    virtual GpgME::Error auditLogError() const;
    bool isAuditLogSupported() const;

    /** Get the underlying context to set some additional options for a job.
     *
     * This is intended to provide more flexibility on configuring jobs before
     * they are started.
     * The context is still owned by the thread, do not delete it.
     *
     * This is a static method that takes the job as argument.
     *
     * This function may not be called for running jobs.
     *
     * @returns the context used by the job job or null.
     */
    static GpgME::Context *context(Job *job);

    /** Starts the job.
     *
     * Starts the job with the values set for the concrete job. If starting
     * the job failed then you are responsible for destroying it. Therefore,
     * it's recommended to store the job in a std::unique_ptr until it has
     * been started successfully.
     */
    GpgME::Error startIt();

    /** Starts a deferred job.
     *
     * The job needs to have been prepared for a deferred start by calling the
     * startLater() function instead of the start() function of a leaf class.
     */
    void startNow();

public Q_SLOTS:
    virtual void slotCancel() = 0;

Q_SIGNALS:
    /**
     * This signal is emitted whenever the backend sends a progress status
     * message. For most jobs, \a current is the amount of processed data
     * (or files) and \a total is the total amount of data (of files). If
     * \a total is 0, then the total amount is unknown or not yet known.
     * For GnuPG 2.1.13 and later, \a current and \a total do not exceed
     * 2^20, i.e. for larger values they are scaled down and you should not
     * assume that they represent absolute values.
     *
     * Check the documentation on progress in the GpgME manual for details.
     *
     * Note: Some jobs provide special progress signals, e.g. for file-count-
     * or data-based progress.
     */
    void jobProgress(int current, int total);

    /**
     * This signal is emitted whenever the backend sends a progress status
     * message. Compared to the jobProgress signal this signal also provides the
     * what value and the type value reported by the backend. Usually, these
     * values can safely be ignored, so that you are better off using the
     * simpler jobProgress signal.
     * Check the documentation on progress in the GpgME manual for details
     * on what and type.
     *
     * Note: Some jobs provide special progress signals, so that you do not
     * have to deal with what and type yourself.
     */
    void rawProgress(const QString &what, int type, int current, int total);

    QGPGME_DEPRECATED void progress(const QString &what, int current, int total);

    void done();
};

extern QMap <Job *, GpgME::Context *> g_context_map;
}

#endif // __KLEO_JOB_H__

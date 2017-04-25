/*
  eventloopinteractor.h
  Copyright (C) 2003,2004 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

  This file is part of GPGME++.

  GPGME++ is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  GPGME++ is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Library General Public License for more details.

  You should have received a copy of the GNU Library General Public License
  along with GPGME++; see the file COPYING.LIB.  If not, write to the
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

// -*- c++ -*-
#ifndef __GPGMEPP_EVENTLOOPINTERACTOR_H__
#define __GPGMEPP_EVENTLOOPINTERACTOR_H__

#include "gpgmepp_export.h"

namespace GpgME
{

class Context;
class Error;
class TrustItem;
class Key;

/*! \file eventloopinteractor.h
    \brief Abstract base class for gpgme's external event loop support

    This class does most of the work involved with hooking GpgME++
    up with external event loops, such as the GTK or Qt ones.

    It actually provides two interfaces: An interface to the gpgme
    IO Callback handling and one for gpgme events. The IO Callback
    interface consists of the three methods \c actOn(), \c
    registerWatcher() and \c unregisterWatcher(). The event
    interface consists of the three methods \c nextTrustItemEvent(),
    \c nextKeyEvent() and \c operationDoneEvent().

    \sect General Usage

    \c EventLoopInteractor is designed to be used as a
    singleton. However, in order to make any use of it, you have to
    subclass it and reimplement it's pure virtual methods (see
    below). We suggest you keep the constructor protected and
    provide a static \c instance() method that returns the single
    instance. Alternatively, you can create an instance on the
    stack, e.g. in \c main().

    If you want \c EventLoopInteractor to manage a particular \c
    Context, just call \c manage() on the \c Context. OTOH, if you
    want to disable IO callbacks for a \c Context, use \c unmanage().

    \sect IO Callback Interface

    One part of this interface is represented by \c
    registerWatcher() and \c unregisterWatcher(), both of which are
    pure virtual. \c registerWatcher() should do anything necessary
    to hook up watching of file descriptor \c fd for reading (\c dir
    = \c Read) or writing (\c dir = Write) to the event loop you use
    and return a tag identifying that particular watching process
    uniquely. This could be the index into an array of objects you
    use for that purpose or the address of such an object. E.g. in
    Qt, you'd essentially just create a new \c QSocketNotifier:

    \verbatim
    void * registerWatcher( int fd, Direction dir ) {
      return new QSocketNotifier( fd, dir == Read ? QSocketNotifier::Read : QSocketNotifier::Write );
      // misses connecting to the activated() signal...
    }
    \endverbatim

    which uses the address of the created object as unique tag. The
    tag returned by \c registerWatcher is stored by \c
    EventLoopInteractor and passed as argument to \c
    unregisterWatcher(). So, in the picture above, you'd implement \c
    unregisterWatcher() like this:

    \verbatim
    void unregisterWatcher( void * tag ) {
      delete static_cast<QSocketNotifier*>( tag );
    }
    \endverbatim

    The other part of the IO callback interface is \c actOn(), which
    you should call if you receive notification from your event loop
    about activity on file descriptor \c fd in direction \c dir. In
    the picture above, you'd call this from the slot connected to
    the socket notifier's \c activated() signal.

    \note \c registerWatcher() as well as \c unregisterWatcher() may
    be called from within \c actOn(), so be careful with
    e.g. locking in threaded environments and keep in mind that the
    object you used to find the \c fd and \c dir fo the \c actOn()
    call might be deleted when \c actOn() returns!

    \sect Event Handler Interface

*/
class GPGMEPP_EXPORT EventLoopInteractor
{
protected:
    EventLoopInteractor();
public:
    virtual ~EventLoopInteractor();

    static EventLoopInteractor *instance()
    {
        return mSelf;
    }

    void manage(Context *context);
    void unmanage(Context *context);

    enum Direction { Read, Write };
protected:
    //
    // IO Notification Interface
    //

    /** Call this if your event loop detected activity on file
        descriptor fd, with direction dir */
    void actOn(int fd, Direction dir);

    virtual void *registerWatcher(int fd, Direction dir, bool &ok) = 0;
    virtual void unregisterWatcher(void *tag) = 0;

    //
    // Event Handler Interface
    //

    virtual void operationStartEvent(Context *context) = 0;
    virtual void nextTrustItemEvent(Context *context, const TrustItem &item) = 0;
    virtual void nextKeyEvent(Context *context, const Key &key) = 0;
    virtual void operationDoneEvent(Context *context, const Error &e) = 0;

private:
    class Private;
    friend class Private;
    Private *const d;
    static EventLoopInteractor *mSelf;
};

}

#endif // __GPGMEPP_EVENTLOOPINTERACTOR_H__

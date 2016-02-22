/*
  eventloopinteractor.cpp
  Copyright (C) 2003,2004 Klarälvdalens Datakonsult AB

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

#include <config-gpgme++.h>

#include <eventloopinteractor.h>

#include <context.h>
#include "context_p.h"
#include <key.h>
#include <trustitem.h>

#include <gpgme.h>

#include <vector>
using std::vector;
#ifndef NDEBUG
# include <iostream>
#endif
#include <cassert>

namespace GpgME
{

//
// EventLoopInteractor::Private Declaration
//

class EventLoopInteractor::Private
{
public:
    struct OneFD {
        OneFD(int aFd, int aDir, gpgme_io_cb_t aFnc,
              void *aFncData, void *aExternalTag)
            : fd(aFd), dir(aDir), fnc(aFnc),
              fncData(aFncData), externalTag(aExternalTag) {}
        int fd;
        int dir;
        gpgme_io_cb_t fnc;
        void *fncData;
        void *externalTag;
    };

    vector<OneFD *> mCallbacks;

    static void removeIOCb(void *tag);
    static gpgme_error_t registerIOCb(void *data, int fd, int dir,
                                      gpgme_io_cb_t fnc, void *fnc_data,
                                      void **r_tag);
    static void eventIOCb(void *, gpgme_event_io_t type, void *type_data);

    static const gpgme_io_cbs iocbs;
};

const gpgme_io_cbs EventLoopInteractor::Private::iocbs = {
    &EventLoopInteractor::Private::registerIOCb,
    0,
    &EventLoopInteractor::Private::removeIOCb,
    &EventLoopInteractor::Private::eventIOCb,
    0
};

//
// EventLoopInteractor::Private IO Callback Implementations
//

gpgme_error_t EventLoopInteractor::Private::registerIOCb(void *, int fd, int dir,
        gpgme_io_cb_t fnc, void *fnc_data,
        void **r_tag)
{
    assert(instance()); assert(instance()->d);
    bool ok = false;
    void *etag = instance()->registerWatcher(fd, dir ? Read : Write, ok);
    if (!ok) {
        return gpgme_error(GPG_ERR_GENERAL);
    }
    instance()->d->mCallbacks.push_back(new OneFD(fd, dir, fnc, fnc_data, etag));
    if (r_tag) {
        *r_tag = instance()->d->mCallbacks.back();
    }
    return GPG_ERR_NO_ERROR;
}

void EventLoopInteractor::Private::removeIOCb(void *tag)
{

    if (!instance() || !instance()->d) {
        return;
    }
    for (vector<OneFD *>::iterator it = instance()->d->mCallbacks.begin();
            it != instance()->d->mCallbacks.end() ; ++it) {
        if (*it == tag) {
            instance()->unregisterWatcher((*it)->externalTag);
            delete *it; *it = 0;
            instance()->d->mCallbacks.erase(it);
            return;
        }
    }
}

void EventLoopInteractor::Private::eventIOCb(void *data, gpgme_event_io_t type, void *type_data)
{
    assert(instance());
    Context *ctx = static_cast<Context *>(data);
    switch (type) {
    case GPGME_EVENT_START: {
        instance()->operationStartEvent(ctx);
        // TODO: what's in type_data?
    }
    break;
    case GPGME_EVENT_DONE: {
        gpgme_error_t e = *static_cast<gpgme_error_t *>(type_data);
        if (ctx && ctx->impl()) {
            ctx->impl()->lasterr = e;
        }
        instance()->operationDoneEvent(ctx, Error(e));
    }
    break;
    case GPGME_EVENT_NEXT_KEY: {
        gpgme_key_t key = static_cast<gpgme_key_t>(type_data);
        instance()->nextKeyEvent(ctx, Key(key, false));
    }
    break;
    case GPGME_EVENT_NEXT_TRUSTITEM: {
        gpgme_trust_item_t item = static_cast<gpgme_trust_item_t>(type_data);
        instance()->nextTrustItemEvent(ctx, TrustItem(item));
        gpgme_trust_item_unref(item);
    }
    break;
    default: // warn
        ;
    }
}

//
// EventLoopInteractor Implementation
//

EventLoopInteractor *EventLoopInteractor::mSelf = 0;

EventLoopInteractor::EventLoopInteractor() : d(new Private)
{
    assert(!mSelf);
    mSelf = this;
}

EventLoopInteractor::~EventLoopInteractor()
{
    // warn if there are still callbacks registered
    mSelf = 0;
    delete d;
}

void EventLoopInteractor::manage(Context *context)
{
    if (!context || context->managedByEventLoopInteractor()) {
        return;
    }
    gpgme_io_cbs *iocbs = new gpgme_io_cbs(Private::iocbs);
    iocbs->event_priv = context;
    context->installIOCallbacks(iocbs);
}

void EventLoopInteractor::unmanage(Context *context)
{
    if (context) {
        context->uninstallIOCallbacks();
    }
}

void EventLoopInteractor::actOn(int fd, Direction dir)
{
    for (vector<Private::OneFD *>::const_iterator it = d->mCallbacks.begin();
            it != d->mCallbacks.end() ; ++it) {
        if ((*it)->fd == fd && ((*it)->dir ? Read : Write) == dir) {
            (*((*it)->fnc))((*it)->fncData, fd);
            break;
        }
    }
}

} // namespace GpgME

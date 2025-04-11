/*
  gpgsignkeyeditinteractor.cpp - Edit Interactor to change the expiry time of an OpenPGP key
  Copyright (C) 2007 Klarälvdalens Datakonsult AB
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

#ifdef HAVE_CONFIG_H
 #include "config.h"
#endif

#include "gpgsignkeyeditinteractor.h"
#include "error.h"
#include "key.h"

#include <gpgme.h>

#include <map>
#include <string>
#include <sstream>

#include <cassert>
#include <cstring>

using std::strcmp;

// avoid conflict (msvc)
#ifdef ERROR
# undef ERROR
#endif

#ifdef _MSC_VER
#undef snprintf
#define snprintf _snprintf
#endif

using namespace GpgME;

class GpgSignKeyEditInteractor::Private
{
public:
    Private();

    std::string scratch;
    bool started;
    int options;
    std::vector<unsigned int> userIDs;
    std::vector<unsigned int>::const_iterator currentId, nextId;
    unsigned int checkLevel;
    bool dupeOk;
    Key key;
    struct {
        TrustSignatureTrust trust;
        std::string depth;
        std::string scope;
    } trustSignature;

    const char *command() const
    {
        const bool local = (options & Exportable) == 0;
        const bool nonRevoc = options & NonRevocable;
        const bool trust = options & Trust;
        //TODO: check if all combinations are valid
        if (local && nonRevoc && trust) {
            return "ltnrsign";
        }
        if (local && nonRevoc) {
            return "lnrsign";
        }
        if (local && trust) {
            return "ltsign";
        }
        if (local) {
            return "lsign";
        }
        if (nonRevoc && trust) {
            return "tnrsign";
        }
        if (nonRevoc) {
            return "nrsign";
        }
        if (trust) {
            return "tsign";
        }
        return "sign";
    }

    bool signAll() const
    {
        return userIDs.empty();
    }
    unsigned int nextUserID()
    {
        assert(nextId != userIDs.end());
        currentId = nextId++;
        return currentUserID();
    }

    bool allUserIDsListed() const
    {
        return nextId == userIDs.end();
    }

    unsigned int currentUserID() const
    {
        assert(currentId != userIDs.end());
        return *currentId + 1;
    }

};

GpgSignKeyEditInteractor::Private::Private()
    :
    started(false),
    options(0),
    userIDs(),
    currentId(),
    nextId(),
    checkLevel(0),
    dupeOk(false),
    trustSignature{TrustSignatureTrust::None, "0", {}}
{
}

GpgSignKeyEditInteractor::GpgSignKeyEditInteractor()
    : EditInteractor(), d(new Private)
{

}

GpgSignKeyEditInteractor::~GpgSignKeyEditInteractor()
{
    delete d;
}

// work around --enable-final
namespace GpgSignKeyEditInteractor_Private
{
enum SignKeyState {
    START = EditInteractor::StartState,
    COMMAND,
    UIDS_ANSWER_SIGN_ALL,
    UIDS_LIST_SEPARATELY,
    // all these free slots belong to UIDS_LIST_SEPARATELY, too
    // (we increase state() by one for each UID, so that action() is called)
    UIDS_LIST_SEPARATELY_DONE = 1000000,
    SET_EXPIRE,
    SET_CHECK_LEVEL,
    SET_TRUST_VALUE,
    SET_TRUST_DEPTH,
    SET_TRUST_REGEXP,
    CONFIRM,
    CONFIRM2,
    DUPE_OK,
    DUPE_OK2,
    REJECT_SIGN_EXPIRED,
    QUIT,
    SAVE,
    ERROR = EditInteractor::ErrorState
};

typedef std::map<std::tuple<SignKeyState, unsigned int, std::string>, SignKeyState> TransitionMap;

}

static const char *answer(bool b)
{
    return b ? "Y" : "N";
}

static GpgSignKeyEditInteractor_Private::TransitionMap makeTable()
{
    using namespace GpgSignKeyEditInteractor_Private;
    TransitionMap tab;
    const unsigned int GET_BOOL = GPGME_STATUS_GET_BOOL;
    const unsigned int GET_LINE = GPGME_STATUS_GET_LINE;
#define addEntry( s1, status, str, s2 ) tab[std::make_tuple( s1, status, str)] = s2
    addEntry(START, GET_LINE, "keyedit.prompt", COMMAND);
    addEntry(COMMAND, GET_BOOL, "keyedit.sign_all.okay", UIDS_ANSWER_SIGN_ALL);
    addEntry(COMMAND, GET_BOOL, "sign_uid.expired_okay", REJECT_SIGN_EXPIRED);
    addEntry(COMMAND, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(COMMAND, GET_BOOL, "sign_uid.local_promote_okay", CONFIRM);
    addEntry(COMMAND, GET_BOOL, "sign_uid.dupe_okay", DUPE_OK);
    addEntry(COMMAND, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(UIDS_ANSWER_SIGN_ALL, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(UIDS_ANSWER_SIGN_ALL, GET_BOOL, "sign_uid.dupe_okay", DUPE_OK);
    addEntry(UIDS_ANSWER_SIGN_ALL, GET_LINE, "sign_uid.expire", SET_EXPIRE);
    addEntry(UIDS_ANSWER_SIGN_ALL, GET_LINE, "sign_uid.class", SET_CHECK_LEVEL);
    addEntry(UIDS_ANSWER_SIGN_ALL, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(SET_TRUST_VALUE, GET_LINE, "trustsig_prompt.trust_depth", SET_TRUST_DEPTH);
    addEntry(SET_TRUST_DEPTH, GET_LINE, "trustsig_prompt.trust_regexp", SET_TRUST_REGEXP);
    addEntry(SET_TRUST_REGEXP, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(SET_CHECK_LEVEL, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(SET_EXPIRE, GET_BOOL, "sign_uid.class", SET_CHECK_LEVEL);
    addEntry(CONFIRM, GET_BOOL, "sign_uid.local_promote_okay", CONFIRM2);
    addEntry(CONFIRM2, GET_BOOL, "sign_uid.local_promote_okay", CONFIRM);
    addEntry(DUPE_OK, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(DUPE_OK2, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(DUPE_OK, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(DUPE_OK2, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(CONFIRM, GET_BOOL, "sign_uid.okay", CONFIRM2);
    addEntry(CONFIRM2, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(CONFIRM, GET_LINE, "keyedit.prompt", COMMAND);
    addEntry(CONFIRM2, GET_LINE, "keyedit.prompt", COMMAND);
    addEntry(CONFIRM, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(CONFIRM2, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(CONFIRM, GET_LINE, "sign_uid.expire", SET_EXPIRE);
    addEntry(CONFIRM2, GET_LINE, "sign_uid.expire", SET_EXPIRE);
    addEntry(CONFIRM, GET_LINE, "sign_uid.class", SET_CHECK_LEVEL);
    addEntry(CONFIRM2, GET_LINE, "sign_uid.class", SET_CHECK_LEVEL);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_BOOL, "sign_uid.local_promote_okay", CONFIRM);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_LINE, "keyedit.prompt", COMMAND);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_LINE, "trustsig_prompt.trust_value", SET_TRUST_VALUE);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_LINE, "sign_uid.expire", SET_EXPIRE);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_LINE, "sign_uid.class", SET_CHECK_LEVEL);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_BOOL, "sign_uid.okay", CONFIRM);
    addEntry(UIDS_LIST_SEPARATELY_DONE, GET_BOOL, "sign_uid.dupe_okay", DUPE_OK);
    addEntry(DUPE_OK, GET_BOOL, "sign_uid.dupe_okay", DUPE_OK2);
    addEntry(DUPE_OK2, GET_BOOL, "sign_uid.dupe_okay", DUPE_OK);
    addEntry(CONFIRM, GET_LINE, "keyedit.prompt", QUIT);
    addEntry(REJECT_SIGN_EXPIRED, GET_LINE, "keyedit.prompt", QUIT);
    addEntry(ERROR, GET_LINE, "keyedit.prompt", QUIT);
    addEntry(QUIT, GET_BOOL, "keyedit.save.okay", SAVE);
#undef addEntry
    return tab;
}

const char *GpgSignKeyEditInteractor::action(Error &err) const
{
    static const char check_level_strings[][2] = { "0", "1", "2", "3" };
    using namespace GpgSignKeyEditInteractor_Private;
    using namespace std;

    switch (const unsigned int st = state()) {
    case COMMAND:
        return d->command();
    case UIDS_ANSWER_SIGN_ALL:
        return answer(d->signAll());
    case UIDS_LIST_SEPARATELY_DONE:
        return d->command();
    case SET_EXPIRE:
        return answer(true);
    case SET_TRUST_VALUE:
        return d->trustSignature.trust == TrustSignatureTrust::Partial ? "1" : "2";
    case SET_TRUST_DEPTH:
        return d->trustSignature.depth.c_str();
    case SET_TRUST_REGEXP:
        return d->trustSignature.scope.c_str();
    case SET_CHECK_LEVEL:
        return check_level_strings[d->checkLevel];
    case DUPE_OK:
    case DUPE_OK2:
        return answer(d->dupeOk);
    case CONFIRM2:
    case CONFIRM:
        return answer(true);
    case REJECT_SIGN_EXPIRED:
        err = Error::fromCode(GPG_ERR_KEY_EXPIRED);
        return answer(false);
    case QUIT:
        return "quit";
    case SAVE:
        return answer(true);
    default:
        if (st >= UIDS_LIST_SEPARATELY && st < UIDS_LIST_SEPARATELY_DONE) {
            std::stringstream ss;
            auto nextID = d->nextUserID();
            const char *hash;
            assert (nextID);
            if (!d->key.isNull() && (hash = d->key.userID(nextID - 1).uidhash())) {
                /* Prefer uidhash if it is available as it might happen
                 * that uidattrs break the ordering of the uids in the
                 * edit-key interface */
                ss << "uid " << hash;
            } else {
                ss << nextID;
            }
            d->scratch = ss.str();
            return d->scratch.c_str();
        }
    // fall through
    case ERROR:
        err = Error::fromCode(GPG_ERR_GENERAL);
        return nullptr;
    }
}

unsigned int GpgSignKeyEditInteractor::nextState(unsigned int status, const char *args, Error &err) const
{
    d->started = true;
    using namespace GpgSignKeyEditInteractor_Private;
    static const Error GENERAL_ERROR = Error::fromCode(GPG_ERR_GENERAL);
    //static const Error INV_TIME_ERROR = Error::fromCode( GPG_ERR_INV_TIME );
    static const TransitionMap table(makeTable());

    using namespace GpgSignKeyEditInteractor_Private;

    //lookup transition in map
    const TransitionMap::const_iterator it = table.find(std::make_tuple(static_cast<SignKeyState>(state()), status, std::string(args)));
    if (it != table.end()) {
        return it->second;
    }

    //handle cases that cannot be handled via the map
    switch (const unsigned int st = state()) {
    case UIDS_ANSWER_SIGN_ALL:
        if (status == GPGME_STATUS_GET_LINE &&
                strcmp(args, "keyedit.prompt") == 0) {
            if (!d->signAll()) {
                return UIDS_LIST_SEPARATELY;
            }
            err = Error::fromCode(GPG_ERR_UNUSABLE_PUBKEY);
            return ERROR;
        }
        break;
    default:
        if (st >= UIDS_LIST_SEPARATELY && st < UIDS_LIST_SEPARATELY_DONE) {
            if (status == GPGME_STATUS_GET_LINE &&
                    strcmp(args, "keyedit.prompt") == 0) {
                return d->allUserIDsListed() ? UIDS_LIST_SEPARATELY_DONE : st + 1 ;
            }
        }
        break;
    case CONFIRM:
    case ERROR:
        err = lastError();
        return ERROR;
    }

    err = GENERAL_ERROR;
    return ERROR;
}
void GpgSignKeyEditInteractor::setKey(const Key &key)
{
    d->key = key;
}

void GpgSignKeyEditInteractor::setCheckLevel(unsigned int checkLevel)
{
    assert(!d->started);
    assert(checkLevel <= 3);
    d->checkLevel = checkLevel;
}

void GpgSignKeyEditInteractor::setUserIDsToSign(const std::vector<unsigned int> &userIDsToSign)
{
    assert(!d->started);
    d->userIDs = userIDsToSign;
    d->nextId = d->userIDs.begin();
    d->currentId = d->userIDs.end();

}
void GpgSignKeyEditInteractor::setSigningOptions(int options)
{
    assert(!d->started);
    d->options = options;
}

void GpgSignKeyEditInteractor::setDupeOk(bool value)
{
    assert(!d->started);
    d->dupeOk = value;
}

void GpgSignKeyEditInteractor::setTrustSignatureTrust(GpgME::TrustSignatureTrust trust)
{
    assert(!d->started);
    assert(trust != TrustSignatureTrust::None);
    d->trustSignature.trust = trust;
}

void GpgSignKeyEditInteractor::setTrustSignatureDepth(unsigned short depth)
{
    assert(!d->started);
    assert(depth <= 255);
    d->trustSignature.depth = std::to_string(depth);
}

void GpgSignKeyEditInteractor::setTrustSignatureScope(const std::string &scope)
{
    assert(!d->started);
    d->trustSignature.scope = scope;
}

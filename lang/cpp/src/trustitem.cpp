/*
  trustitem.cpp - wraps a gpgme trust item
  Copyright (C) 2003 Klarälvdalens Datakonsult AB
  2016 Bundesamt für Sicherheit in der Informationstechnik
  Software engineering by Intevation GmbH

  This file is part of GPGME.

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

#include <trustitem.h>

#include <gpgme.h>

#include <cassert>

namespace GpgME
{

class TrustItem::Private
{
public:
    Private(gpgme_trust_item_t aItem)
        : item(aItem)
    {
    }

    gpgme_trust_item_t item;
};

TrustItem::TrustItem(gpgme_trust_item_t item)
{
    d = new Private(item);
    if (d->item) {
        gpgme_trust_item_ref(d->item);
    }
}

TrustItem::TrustItem(const TrustItem &other)
{
    d = new Private(other.d->item);
    if (d->item) {
        gpgme_trust_item_ref(d->item);
    }
}

TrustItem::~TrustItem()
{
    if (d->item) {
        gpgme_trust_item_unref(d->item);
    }
    delete d; d = nullptr;
}

bool TrustItem::isNull() const
{
    return !d || !d->item;
}

gpgme_trust_item_t TrustItem::impl() const
{
    return d->item;
}

const char *TrustItem::keyID() const
{
    return d->item ? d->item->keyid : nullptr ;
}

const char *TrustItem::userID() const
{
    return d->item ? d->item->name : nullptr ;
}

const char *TrustItem::ownerTrustAsString() const
{
    return d->item ? d->item->owner_trust : nullptr ;
}

const char *TrustItem::validityAsString() const
{
    return d->item ? d->item->validity : nullptr ;
}

int TrustItem::trustLevel() const
{
    return d->item ? d->item->level : 0 ;
}

TrustItem::Type TrustItem::type() const
{
    if (!d->item) {
        return Unknown;
    } else {
        return
            d->item->type == 1 ? Key :
            d->item->type == 2 ? UserID :
            Unknown ;
    }
}

} // namespace GpgME

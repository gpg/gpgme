/* ignupg.c - COM+ class IGnuPG
 *	Copyright (C) 2000 Werner Koch (dd9jn)
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <windows.h>

#define INITGUID
#include "ignupg.h"

/*
 * Declare the interface implementation structures
 */
typedef struct IGnuPGImpl IGnuPGImpl;
typedef struct IClassFactoryImpl IClassFactoryImpl;


struct IGnuPGImpl {
    /* IUnknown required stuff */
    ICOM_VFIELD (IGnuPG);
    DWORD	 ref;
    /* Our stuff */
    int foo;
};


struct IClassFactoryImpl {
    /* IUnknown fields */
    ICOM_VFIELD(IClassFactory);
    DWORD       ref;
};



/**********************************************************
 **************  IGnuPG Implementation  *******************
 **********************************************************/

static HRESULT WINAPI
IGnuPGImpl_QueryInterface (IGnuPG *iface, REFIID refiid, LPVOID *obj)
{
    ICOM_THIS (IGnuPGImpl,iface);

    fprintf (stderr,"(%p)->QueryInterface(%s,%p)\n",
             This, "debugstr_guid(refiid)", obj);
    if ( IsEqualGUID (&IID_IUnknown, refiid)
         || !IsEqualGUID (&IID_IGnuPG, refiid) ) {
        *obj = iface;
        return 0;
    }
    *obj = NULL;
    return E_NOINTERFACE;
}


static ULONG WINAPI
IGnuPGImpl_AddRef (IGnuPG *iface)
{
    ICOM_THIS (IGnuPGImpl,iface);
	
    return ++This->ref;
}


static ULONG WINAPI
IGnuPGImpl_Release (IGnuPG *iface)
{
    ICOM_THIS (IGnuPGImpl,iface);
	
    if (--This->ref)
        return This->ref;

    HeapFree(GetProcessHeap(),0,iface);
    return 0;
}




static ICOM_VTABLE(IGnuPG) gnupg_vtbl = 
{
    /* IUnknow methods */
    ICOM_MSVTABLE_COMPAT_DummyRTTIVALUE
    IGnuPGImpl_QueryInterface,
    IGnuPGImpl_AddRef,
    IGnuPGImpl_Release,
    /* Our methods */

};



/***************************************************************
 ******************  GnuPG Factory  ****************************
 ***************************************************************/

static HRESULT WINAPI 
GnuPGFactory_QueryInterface (IClassFactory *iface, REFIID refiid, LPVOID *obj)
{
    /*ICOM_THIS(IClassFactoryImpl,iface);*/
    return E_NOINTERFACE;
}

static ULONG WINAPI
GnuPGFactory_AddRef (IClassFactory *iface)
{
    ICOM_THIS(IClassFactoryImpl,iface);
    return ++(This->ref);
}

static ULONG WINAPI
GnuPGFactory_Release (IClassFactory *iface)
{
    ICOM_THIS(IClassFactoryImpl,iface);
    return --(This->ref);
}

static HRESULT WINAPI
GnuPGFactory_CreateInstance (IClassFactory *iface, IUnknown *outer,
                             REFIID refiid, LPVOID *r_obj )
{
    /*ICOM_THIS(IClassFactoryImpl,iface);*/

    if ( IsEqualGUID (&IID_IGnuPG, refiid) ) {
	IGnuPGImpl *obj;

	obj = HeapAlloc (GetProcessHeap(), 0, sizeof *obj );
	if ( !obj)
            return E_OUTOFMEMORY;

	ICOM_VTBL(obj) = &gnupg_vtbl;
	obj->ref = 1;
        *r_obj = obj;
	return 0;
    }
    *r_obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI
GnuPGFactory_LockServer (IClassFactory *iface, BOOL dolock )
{
    /*ICOM_THIS(IClassFactoryImpl,iface);*/
    return 0;
}

static ICOM_VTABLE(IClassFactory) gnupg_factory_vtbl = {
    ICOM_MSVTABLE_COMPAT_DummyRTTIVALUE
    GnuPGFactory_QueryInterface,
    GnuPGFactory_AddRef,
    GnuPGFactory_Release,
    GnuPGFactory_CreateInstance,
    GnuPGFactory_LockServer
};
static IClassFactoryImpl GnuPG_CF = {&gnupg_factory_vtbl, 1 };


IClassFactory *
gnupg_factory_new ( CLSID *r_clsid )
{
    *r_clsid = CLSID_GnuPG;
    IClassFactory_AddRef((IClassFactory*)&GnuPG_CF);
    return (IClassFactory*)&GnuPG_CF;
}

void
gnupg_factory_release ( IClassFactory *factory )
{
    /* it's static - nothing to do */
}










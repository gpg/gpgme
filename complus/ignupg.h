/* ignupg.h - COM+ class IGnuPG
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

#ifndef IGNUPG_H
#define IGNUPG_H 1

#include "obj_base.h"

DEFINE_GUID(CLSID_GnuPG,      0x42424242, 0x62e8, 0x11cf,
                              0x93, 0xbc, 0x44, 0x45, 0x53, 0x54, 0x0, 0x0);
DEFINE_GUID(IID_IGnuPG,       0x24242424, 0x4981, 0x11CE,
                              0xA5,0x21,0x00,0x20,0xAF,0x0B,0xE5,0x60);
typedef struct IGnuPG IGnuPG;



#define ICOM_INTERFACE IGnuPG

#define IGnuPG_METHODS \
    ICOM_METHOD1(HRESULT,Initialize,    REFIID,) \
    ICOM_METHOD1(HRESULT,EnumDevices,   LPVOID,) 

#define IGnuPG_IMETHODS \
    IUnknown_IMETHODS \
    IGnuPG_METHODS

ICOM_DEFINE(IGnuPG,IUnknown)
#undef ICOM_INTERFACE


/*** IUnknown methods ***/
#define IGnuPG_QueryInterface(p,a,b) ICOM_CALL2(QueryInterface,p,a,b)
#define IGnuPG_AddRef(p)             ICOM_CALL (AddRef,p)
#define IGnuPG_Release(p)            ICOM_CALL (Release,p)
/*** IGnuPG methods ***/
#define IGnuPG_Initialize(p,a)       ICOM_CALL1(Initialize,p,a)
#define IGnuPG_EnumDevices(p,a,b)    ICOM_CALL2(EnumDevice,p,a,b)


#endif /*IGNUPG_H*/












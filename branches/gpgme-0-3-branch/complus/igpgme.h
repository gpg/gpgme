/* igpgme.h - COM+ class IGpgme
 *	Copyright (C) 2001 g10 Code GmbH
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

#ifndef IGPGME_H
#define IGPGME_H 1

#include <ole2.h>

DEFINE_GUID(CLSID_Gpgme,      0x3811fd40, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);
#if 0
DEFINE_GUID(CLSID_GpgmeData,  0x3811fd41, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);
DEFINE_GUID(CLSID_GpgmeKey,   0x3811fd42, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);
DEFINE_GUID(CLSID_GpgmeRSet,  0x3811fd43, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);
#endif

DEFINE_GUID(TLBID_Gpgcom,     0x3811fd48, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);
DEFINE_GUID(APPID_Gpgcom,     0x3811fd4f, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);


DEFINE_GUID(IID_IGpgme,       0x3811fd50, 0x7f72, 0x11d5,
            0x8c, 0x9e, 0x00, 0x80, 0xad, 0x19, 0x0c, 0xd5);

typedef struct IGpgme IGpgme;

void igpgme_register_exit_event (HANDLE ev);
IClassFactory *igpgme_factory_new( CLSID *r_clsid );
void igpgme_factory_release ( IClassFactory *factory );


/********************************************
 ***** The IGpgme interface *****************
 ********************************************/

#define ICOM_INTERFACE IGpgme

#define IGpgme_METHODS \
    ICOM_METHOD1(HRESULT,GetVersion,    BSTR*,) \
    ICOM_METHOD1(HRESULT,GetEngineInfo, BSTR*,) \
    ICOM_METHOD(HRESULT,Cancel)               \
    ICOM_METHOD1(HRESULT,SetArmor,BOOL,)        \
    ICOM_METHOD1(HRESULT,GetArmor,BOOL*,)       \
    ICOM_METHOD1(HRESULT,SetTextmode,BOOL,)     \
    ICOM_METHOD1(HRESULT,GetTextmode,BOOL*,)    \
    ICOM_METHOD1(HRESULT,SetPlaintext,VARIANT,)    \
    ICOM_METHOD1(HRESULT,GetPlaintext,VARIANT*,)   \
    ICOM_METHOD1(HRESULT,SetCiphertext,VARIANT,)   \
    ICOM_METHOD1(HRESULT,GetCiphertext,VARIANT*,)  \
    ICOM_METHOD(HRESULT,ClearRecipients)      \
    ICOM_METHOD2(HRESULT,AddRecipient,BSTR,,signed short int,)  \
    ICOM_METHOD(HRESULT,ResetSignKeys)      \
    ICOM_METHOD1(HRESULT,AddSignKey,BSTR,)  \
    ICOM_METHOD(HRESULT,Encrypt)            \
    ICOM_METHOD1(HRESULT,Sign,signed short int,)   \
    ICOM_METHOD1(HRESULT,SignEncrypt,signed short int,)

#if 0
    ICOM_METHOD1(HRESULT,SetKeylistMode,)      
    ICOM_METHOD1(HRESULT,SetPassphraseCB,)      
    ICOM_METHOD1(HRESULT,SetProgressCB,)      
    ICOM_METHOD1(HRESULT,SignersClear,)      
    ICOM_METHOD1(HRESULT,SignersAdd,)      
    ICOM_METHOD1(HRESULT,SignersEnum,)      
    ICOM_METHOD1(HRESULT,GetSigStatus,)   
    ICOM_METHOD1(HRESULT,GetNotation,) 
#endif

#define IGpgme_IMETHODS \
    IDispatch_IMETHODS \
    IGpgme_METHODS

ICOM_DEFINE(IGpgme,IDispatch)
#undef ICOM_INTERFACE


/*** IUnknown methods ***/
#define IGpgme_QueryInterface(p,a,b) ICOM_CALL2(QueryInterface,p,a,b)
#define IGpgme_AddRef(p)             ICOM_CALL (AddRef,p)
#define IGpgme_Release(p)            ICOM_CALL (Release,p)
/*** IGpgme methods ***/
#define IGpgme_GetVersion(p,r)       ICOM_CALL1(GetVersion,p,r)
#define IGpgme_GetEngineInfo(p,r)    ICOM_CALL1(GetEngineInfo,p,r)
#define IGpgme_Cancel(p,a)           ICOM_CALL1(Cancel,p,a)             
#define IGpgme_SetArmor(p,a)         ICOM_CALL1(SetArmor,p,a)      
#define IGpgme_GetArmor(p,a)         ICOM_CALL1(GetArmor,p,a)      
#define IGpgme_SetTextmode(p,a)      ICOM_CALL1(SetTextmode,p,a)      
#define IGpgme_GetTextmode(p,a)      ICOM_CALL1(GetTextmode,p,a)      
#define IGpgme_SetPlaintext(p,a)     ICOM_CALL1(SetPlaintext,p,a)
#define IGpgme_GetPlaintext(p,a)     ICOM_CALL1(GetPlaintext,p,a)
#define IGpgme_SetCiphertext(p,a)    ICOM_CALL1(SetCiphertext,p,a)
#define IGpgme_GetCiphertext(p,a)    ICOM_CALL1(GetCiphertext,p,a)
#define IGpgme_ClearRecipients(p)    ICOM_CALL (ClearRecipients,p)
#define IGpgme_AddRecipient(p,a,b)   ICOM_CALL2(AddRecipient,p,a,b)
#define IGpgme_ResetSignKeys(p)      ICOM_CALL (ResetSignKeys,p)
#define IGpgme_AddSignKey(p,a)       ICOM_CALL (AddSignKey,p,a)
#define IGpgme_Encrypt(p)            ICOM_CALL (Encrypt,p)
#define IGpgme_Sign(p,a)             ICOM_CALL (Sign,p,a)
#define IGpgme_SignEncrypt(p,a)      ICOM_CALL (SignEncrypt,p,a)
#if 0
#define IGpgme_SetKeylistMode(p,a)   ICOM_CALL1(SetKeylistMode,p,a)      
#define IGpgme_SetPassphraseCB(p,a)  ICOM_CALL1(SetPassphraseCB,p,a)     
#define IGpgme_SetProgressCB(p,a)    ICOM_CALL1(SetProgressCB,p,a)     
#define IGpgme_SignersClear(p,a)     ICOM_CALL1(SignersClear,p,a)     
#define IGpgme_SignersAdd(p,a)       ICOM_CALL1(SignersAdd,p,a)     
#define IGpgme_SignersEnum(p,a)      ICOM_CALL1(SignersEnum,p,a)     
#define IGpgme_GetSigStatus(p,a)     ICOM_CALL1(GetSigStatus,p,a)      
#define IGpgme_GetSigKey(p,a)        ICOM_CALL1(GetSigKey,p,a)
#define IGpgme_GetNotation(p,a)      ICOM_CALL1(GetNotation,p,a)      
#endif


#if 0
/********************************************
 ***** The IGpgmeKey interface **************
 ********************************************/

#define ICOM_INTERFACE IGpgmeKey

#define IGpgmeKey_METHODS \
    ICOM_METHOD1(HRESULT,GetVersion,    BSTR,) \
    ICOM_METHOD1(HRESULT,GetEngineInfo, BSTR,)


#define IGpgmeKey_IMETHODS \
    IUnknown_IMETHODS \
    IGpgmeKey_METHODS

ICOM_DEFINE(IGpgmeKey,IUnknown)
#undef ICOM_INTERFACE

/*** IUnknown methods ***/
#define IGpgmeKey_QueryInterface(p,a,b) ICOM_CALL2(QueryInterface,p,a,b)
#define IGpgmeKey_AddRef(p)             ICOM_CALL (AddRef,p)
#define IGpgmeKey_Release(p)            ICOM_CALL (Release,p)
/*** IGpgmeKey methods ***/
#define IGpgmeKey_GetVersion(p,r)       ICOM_CALL1(GetVersion,p,r)
#define IGpgmeKey_GetEngineInfo(p,r)    ICOM_CALL1(GetEngineInfo,p,r)
#endif

#endif /*IGPGME_H*/


/* igpgme.c - COM+ class IGpgme
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


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <windows.h>

#include "../gpgme/gpgme.h"

/* FIXME: Put them into an extra header */
void *_gpgme_malloc (size_t n );
void *_gpgme_calloc (size_t n, size_t m );
void *_gpgme_realloc (void *p, size_t n);
char *_gpgme_strdup (const char *p);
void  _gpgme_free ( void *a );



#define INITGUID
#include "igpgme.h"

/*
 * Declare the interface implementation structures
 */
typedef struct IGpgmeImpl IGpgmeImpl;
typedef struct IClassFactoryImpl IClassFactoryImpl;

static HANDLE my_exit_event;

struct IGpgmeImpl {
    /* IUnknown required stuff */
    ICOM_VFIELD (IGpgme);
    DWORD	 ref;
    /* Delegation to IDispatch */
    struct {
        IUnknown *disp;
        ITypeInfo *tinfo;
    } std_disp;
    /* Our stuff */
    GpgmeCtx mainctx;
    GpgmeData plaintext;
    int plaintext_given_as_bstr;
    GpgmeData ciphertext;
    int ciphertext_is_armored;
    GpgmeRecipients rset;
};


struct IClassFactoryImpl {
    /* IUnknown fields */
    ICOM_VFIELD(IClassFactory);
    DWORD       ref;
};

/**********************************************************
 **************  helper functions  ************************
 *********************************************************/
static HRESULT
map_gpgme_error (GpgmeError err)
{
    HRESULT hr;

    if (!err)
        return 0;
    if ( err < 0 || err > 0x1000 ) {
        fprintf (stderr,"*** GpgmeError `%s' mapped to GPGME_General_Error\n",
                 gpgme_strerror (err) );
        err = GPGME_General_Error;
    }
    hr = MAKE_HRESULT (SEVERITY_ERROR, FACILITY_ITF, 0x1000 + err);
    fprintf (stderr,"*** GpgmeError `%s' mapped to %lx\n",
             gpgme_strerror (err), (unsigned long)hr );
    return hr;
}


/**********************************************************
 **************  IGpgme Implementation  *******************
 *********************************************************/

static HRESULT WINAPI
m_IGpgme_QueryInterface (IGpgme *iface, REFIID refiid, LPVOID *obj)
{
    ICOM_THIS (IGpgmeImpl,iface);

    /*fprintf (stderr,"*** m_IGpgme_QueryInterface(%p,%s)",
      This, debugstr_guid(refiid));*/
    if ( IsEqualGUID (&IID_IUnknown, refiid)
         || IsEqualGUID (&IID_IGpgme, refiid) ) {
        *obj = This;
        IGpgme_AddRef (iface);
        fprintf (stderr," -> got %p\n", *obj);
        return 0;
    }
    else if ( IsEqualGUID (&IID_IDispatch, refiid) ) {
        HRESULT hr = IDispatch_QueryInterface (This->std_disp.disp,
                                               refiid, obj);
        /*fprintf (stderr," -> delegated, hr=%lx, got %p\n",
           hr, hr? NULL: *obj);*/
        return hr;
    }
    /*fprintf (stderr," -> none\n");*/
    *obj = NULL;
    return E_NOINTERFACE;
}


static ULONG WINAPI
m_IGpgme_AddRef (IGpgme *iface)
{
    ICOM_THIS (IGpgmeImpl,iface);
	
    return ++This->ref;
}


static ULONG WINAPI
m_IGpgme_Release (IGpgme *iface)
{
    ICOM_THIS (IGpgmeImpl,iface);
	
    if (--This->ref)
        return This->ref;

    gpgme_release (This->mainctx); This->mainctx = NULL;
    gpgme_data_release (This->plaintext); This->plaintext = NULL;
    gpgme_data_release (This->ciphertext); This->ciphertext = NULL;
    gpgme_recipients_release (This->rset); This->rset = NULL;
    if (This->std_disp.disp)
        IDispatch_Release (This->std_disp.disp);
    if (This->std_disp.tinfo)
        ITypeInfo_Release (This->std_disp.tinfo);
    HeapFree(GetProcessHeap(),0,iface);
    {
        ULONG count = CoReleaseServerProcess ();
        if (!count && my_exit_event)
            SetEvent (my_exit_event);
    }
    return 0;
}


static HRESULT WINAPI
m_stub_IDispatch_GetTypeInfoCount (IGpgme *iface, unsigned int *pctinfo)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI
m_stub_IDispatch_GetTypeInfo (IGpgme *iface, UINT iTInfo,
                              LCID lcid, ITypeInfo **ppTInfo)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI 
m_stub_IDispatch_GetIDsOfNames (IGpgme *iface, REFIID riid, 
                                LPOLESTR *rgszNames, UINT cNames, 
                                LCID lcid, DISPID *rgDispId)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI 
m_stub_IDispatch_Invoke (IGpgme *iface, DISPID dispIdMember, 
                         REFIID riid, LCID lcid, WORD wFlags,
                         DISPPARAMS *pDispParams, VARIANT *pVarResult, 
                         EXCEPINFO *pExepInfo,  UINT *puArgErr)
{
  return E_NOTIMPL;
}



static HRESULT WINAPI
m_IGpgme_GetVersion (IGpgme *iface, BSTR *retvat)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI
m_IGpgme_GetEngineInfo (IGpgme *iface, BSTR *retval)
{
    return E_NOTIMPL;
}


static HRESULT WINAPI
m_IGpgme_Cancel (IGpgme *iface)
{
    return E_NOTIMPL;
}


static HRESULT WINAPI
m_IGpgme_SetArmor (IGpgme *iface, BOOL yes)
{
    ICOM_THIS (IGpgmeImpl,iface);

    gpgme_set_armor (This->mainctx, yes);
    return 0;
}

static HRESULT WINAPI
m_IGpgme_GetArmor (IGpgme *iface, BOOL *retval)
{
    ICOM_THIS (IGpgmeImpl,iface);

    *retval = gpgme_get_armor (This->mainctx);
    return 0;
}


static HRESULT WINAPI
m_IGpgme_SetTextmode (IGpgme *iface, BOOL yes)
{
    ICOM_THIS (IGpgmeImpl,iface);

    gpgme_set_textmode (This->mainctx, yes);
    return 0;
}

static HRESULT WINAPI
m_IGpgme_GetTextmode (IGpgme *iface, BOOL *retval)
{
    ICOM_THIS (IGpgmeImpl,iface);

    *retval = gpgme_get_textmode (This->mainctx);
    return 0;
}


/* 
 * Put the data from VAL into a a Gpgme data object, which is passed by
 * reference.  Valid types of the Variant are: BSTR, SAFEARRAY of BYTE and
 * SAFEARRAY of VARIANTS of signed or unsigned integers.
 */
static HRESULT WINAPI
set_data_from_variant (GpgmeData *data, VARIANT val, int *given_as_bstr)
{
    GpgmeError err = 0;
    HRESULT hr;
    unsigned char *buf;
    SAFEARRAY *array;
    size_t len;
    int i;

    if ( val.vt == VT_BSTR) {
        len = bstrtoutf8 (val.u.bstrVal, NULL, 0);
        buf = _gpgme_malloc (len);
        if (!buf) 
            return E_OUTOFMEMORY;
        
        if (bstrtoutf8 (val.u.bstrVal, buf, len) < 0) {
            fprintf (stderr,"problem with bstrtoutf8\n");
            _gpgme_free (buf);
            return E_FAIL;
        }

        #if 0
        fprintf (stderr,"Got a BSTR (utf8):");
        for (i=0; i < len; i++)
            fprintf (stderr, " %0X", buf[i] );
        putc ('\n', stderr);
        #endif
        gpgme_data_release (*data); *data = NULL; 
        err = gpgme_data_new_from_mem (data, buf, len, 0 /*no need to copy*/ );
        if (!err && given_as_bstr)
            *given_as_bstr = 1;
    }
    else if ( val.vt == (VT_ARRAY|VT_UI1)) {
        array = val.u.parray;

        /*fprintf (stderr,"Got an ARRAY of bytes:");*/
        hr = SafeArrayAccessData (array, (void**)&buf);
        if (hr) {
            fprintf (stderr,"*** SafeArrayAccessData failed: hr=%lx\n", hr);
            return hr;
        }
        len = array->rgsabound[0].cElements;
        /*for (i=0; i < len; i++)
          fprintf (stderr, " %0X", buf[i] );
          putc ('\n', stderr);*/
        
        gpgme_data_release (*data); *data = NULL; 
        err = gpgme_data_new_from_mem (data, buf, len, 1 );
        SafeArrayUnaccessData (array);
        if (given_as_bstr)
            *given_as_bstr = 0;
    }
    else if ( val.vt == (VT_ARRAY|VT_VARIANT)) {
        VARIANT *vp;
        array = val.u.parray;

        /*fprintf (stderr,"Got an ARRAY of VARIANTS:");*/
        hr = SafeArrayAccessData (array, (void**)&vp);
        if (hr) {
            fprintf (stderr,"*** SafeArrayAccessData failed: hr=%lx\n", hr);
            return hr;
        }
        len = array->rgsabound[0].cElements;
        /* allocate the array using the gpgme allocator so that we can
         * later use a new without the copy set*/
        buf = _gpgme_malloc (len);
        if (!buf) {
            SafeArrayUnaccessData (array);
            return E_OUTOFMEMORY;
        }
        /* coerce all array elements into rawtext */
        for (i=0; i < len; i++) {
            switch (vp[i].vt) {
              case VT_I1:   buf[i] = (BYTE)vp[i].u.cVal; break; 
              case VT_I2:   buf[i] = ((UINT)vp[i].u.iVal) & 0xff; break; 
              case VT_I4:   buf[i] = ((ULONG)vp[i].u.lVal) & 0xff; break; 
              case VT_INT:  buf[i] = ((UINT)vp[i].u.intVal) & 0xff; break; 
              case VT_UI1:  buf[i] = vp[i].u.bVal; break; 
              case VT_UI2:  buf[i] = vp[i].u.uiVal & 0xff; break; 
              case VT_UI4:  buf[i] = vp[i].u.ulVal & 0xff; break; 
              case VT_UINT: buf[i] = vp[i].u.uintVal & 0xff; break; 
              default: 
                fprintf (stderr, "Invalid value in array as pos %d\n", i);
                _gpgme_free (buf);
                SafeArrayUnaccessData (array);
                return E_INVALIDARG; 
            }
        }

        /*for (i=0; i < len; i++)
          fprintf (stderr, " %0X", buf[i] );
          putc ('\n', stderr);*/
        
        gpgme_data_release (*data); *data = NULL;
        err = gpgme_data_new_from_mem (data, buf, len, 0);
        SafeArrayUnaccessData (array);
        if (given_as_bstr)
            *given_as_bstr = 0;
    }
    else {
        fprintf (stderr, "Got a variant type = %d (0x%x)\n",
                 (int)val.vt, (int)val.vt );
        return E_INVALIDARG; /* not a safearray of bytes */
    }
    return map_gpgme_error (err);
}


static HRESULT WINAPI
set_data_to_variant (GpgmeData data, VARIANT *retval, int use_bstr)
{
    GpgmeError err;
    HRESULT hr;
    SAFEARRAY *array;
    char *p;
    size_t nread, len;
    int i;

    /* Get some info on the data */
    err = gpgme_data_rewind (data);
    if (err ) {
        fprintf (stderr, "*** gpgme_data_rewind failed: %d\n", err);
        return map_gpgme_error (err);
    }
    err = gpgme_data_read (data, NULL, 0, &nread);
    if (err && err != GPGME_EOF ) {
        fprintf (stderr, "*** gpgme_data_read [length] failed: %d\n", err);
        return map_gpgme_error (err);
    }
    len = nread;  /*(eof returns a length of 0)*/
    /*fprintf (stderr,"*** %d bytes are availabe\n", (int)len);*/

    /* convert it to the target data type */
    if (use_bstr) {
        BSTR bs;
        unsigned char *helpbuf;

        /* It is easier to allocate some helper storage */
        helpbuf = _gpgme_malloc (len);
        if (!helpbuf) 
            return E_OUTOFMEMORY;
        err = gpgme_data_read (data, helpbuf, len, &nread);
        if (err ) {
            _gpgme_free (helpbuf);
            fprintf (stderr, "*** gpgme_data_read [data] failed: %d\n", err);
            return map_gpgme_error (err);
        }

        bs = SysAllocStringLen (NULL, len+1);
        if (!bs) {
            _gpgme_free (helpbuf);
            return E_OUTOFMEMORY;
        }

        for (i=0, p=helpbuf; i < len; i++, p++) 
            bs[i] = *p;
        bs[i] = 0;
        _gpgme_free (helpbuf);

        /* Ready */
        VariantInit (retval);
        retval->vt = VT_BSTR;
        retval->u.bstrVal = bs;
    }
#if 0
    else if (use_byte_array) {
        array = SafeArrayCreateVector (VT_UI1, 0, len);
        if (!array)
            return E_OUTOFMEMORY;

        p = NULL;
        hr = SafeArrayAccessData (array, (void**)&p);
        if (hr) {
            fprintf (stderr,"*** SafeArrayAccessData failed: hr=%lx\n", hr);
            SafeArrayDestroyData (array);
            SafeArrayDestroy (array);
            return hr;
        }
        if (len) {
            err = gpgme_data_read (data, p, len, &nread);
            if (err ) {
                SafeArrayUnaccessData (array);
                SafeArrayDestroyData (array);
                SafeArrayDestroy (array);
                fprintf (stderr, "*** gpgme_data_read [data] failed: %d\n",
                         err);
                return map_gpgme_error (err);
            }
        }
        SafeArrayUnaccessData (array);
        
        /* pass the data to the caller */
        VariantInit (retval);
        retval->vt = (VT_ARRAY|VT_UI1);
        retval->u.parray = array;
    }
#endif
    else { /* Create an array of variants of bytes */
        VARIANT *v;
        unsigned char *helpbuf;

        /* It is easier to allocate some helper storage */
        helpbuf = _gpgme_malloc (len);
        if (!helpbuf)
            return E_OUTOFMEMORY;
        err = gpgme_data_read (data, helpbuf, len, &nread);
        if (err ) {
            _gpgme_free (helpbuf);
            fprintf (stderr, "*** gpgme_data_read [data] failed: %d\n", err);
            return map_gpgme_error (err);
        }

        /* The create the array */
        array = SafeArrayCreateVector (VT_VARIANT, 0, len);
        if (!array) {
            _gpgme_free (helpbuf);
            return E_OUTOFMEMORY;
        }
        
        v = NULL;
        hr = SafeArrayAccessData (array, (void**)&v);
        if (hr) {
            fprintf (stderr,"*** SafeArrayAccessData failed: hr=%lx\n", hr);
            _gpgme_free (helpbuf);
            SafeArrayDestroyData (array);
            SafeArrayDestroy (array);
            return hr;
        }

        for (p=helpbuf; len; len--, v++) {
            VariantInit (v);
            v->vt = VT_UI1;
            v->u.bVal = *p;
        }
        SafeArrayUnaccessData (array);
        _gpgme_free (helpbuf);
        
        /* pass the data to the caller */
        VariantInit (retval);
        retval->vt = (VT_ARRAY|VT_VARIANT);
        retval->u.parray = array;
    }
    return 0;
}


static HRESULT WINAPI
m_IGpgme_SetPlaintext (IGpgme *iface, VARIANT val)
{
    ICOM_THIS (IGpgmeImpl,iface);

    return set_data_from_variant (&This->plaintext, val,
                                  &This->plaintext_given_as_bstr); 
}


static HRESULT WINAPI
m_IGpgme_GetPlaintext (IGpgme *iface, VARIANT *retval)
{
    ICOM_THIS (IGpgmeImpl,iface);

    /*fprintf (stderr,"*** " __PRETTY_FUNCTION__ "(%p)\n", This );*/
    return set_data_to_variant (This->plaintext, retval,
                                This->plaintext_given_as_bstr);
}

static HRESULT WINAPI
m_IGpgme_SetCiphertext (IGpgme *iface, VARIANT val)
{
    ICOM_THIS (IGpgmeImpl,iface);

    return set_data_from_variant (&This->ciphertext, val, NULL); 
}

static HRESULT WINAPI
m_IGpgme_GetCiphertext (IGpgme *iface, VARIANT *retval)
{
    ICOM_THIS (IGpgmeImpl,iface);

    return set_data_to_variant (This->ciphertext, retval,
                                This->ciphertext_is_armored);
}

static HRESULT WINAPI
m_IGpgme_ClearRecipients (IGpgme *iface)
{
    ICOM_THIS (IGpgmeImpl,iface);

    gpgme_recipients_release (This->rset); This->rset = NULL;
    return 0;
}


static HRESULT WINAPI
m_IGpgme_AddRecipient (IGpgme *iface, BSTR name, signed short int trust)
{
    GpgmeError err;
    int n;
    char *p;
    ICOM_THIS (IGpgmeImpl,iface);
    
    /*fprintf (stderr,"*** " __PRETTY_FUNCTION__ "(%p, %d)\n",
      This, (int)trust);*/
    if (!This->rset) {
        err = gpgme_recipients_new (&This->rset);
        if (err)
            return map_gpgme_error (err);
    }

    n = bstrtoutf8 (name, NULL, 0);
    p = HeapAlloc (GetProcessHeap(), 0, n );
    if (!p) {
        fprintf (stderr,"HeapAlloc failed: ec=%d\n", (int)GetLastError () );
        return E_OUTOFMEMORY;
    }
    if (bstrtoutf8 (name, p, n) < 0) {
        fprintf (stderr,"problem with bstrtoutf8\n");
        HeapFree (GetProcessHeap(), 0, p);
        return E_FAIL;
    }
    err = gpgme_recipients_add_name (This->rset, p);
    HeapFree (GetProcessHeap(), 0, p);
    return map_gpgme_error (err);
}

static HRESULT WINAPI
m_IGpgme_ResetSignKeys (IGpgme *iface)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI
m_IGpgme_AddSignKey (IGpgme *iface, BSTR name)
{
    return E_NOTIMPL;
}

static HRESULT WINAPI
m_IGpgme_Encrypt (IGpgme *iface)
{
    GpgmeError err;
    ICOM_THIS (IGpgmeImpl,iface);

    gpgme_data_release (This->ciphertext);
    err = gpgme_data_new (&This->ciphertext);
    if (err)
        return map_gpgme_error (err);

    
    This->ciphertext_is_armored = gpgme_get_armor (This->mainctx);
    err = gpgme_op_encrypt (This->mainctx, This->rset,
                            This->plaintext, This->ciphertext);
#if 0
    if (!err ) {
        char buf[100];
        size_t nread;

        err = gpgme_data_rewind ( This->ciphertext );
        if (err ) 
            fprintf (stderr, "*** gpgme_data_rewind failed: %d\n", err);
        while ( !(err = gpgme_data_read ( This->ciphertext,
                                          buf, 100, &nread )) ) {
            fwrite ( buf, nread, 1, stderr );
        }
        if (err != GPGME_EOF) 
            fprintf (stderr, "*** gpgme_data_read failed: %d\n", err);
        err = 0;
    }
#endif

    return map_gpgme_error (err);
}

static HRESULT WINAPI
m_IGpgme_Sign (IGpgme *iface, short int signmode)
{
    ICOM_THIS (IGpgmeImpl,iface);

    fprintf (stderr,"*** " __PRETTY_FUNCTION__ "(%p)\n", This );

    return E_NOTIMPL;
}

static HRESULT WINAPI
m_IGpgme_SignEncrypt (IGpgme *iface, short int signmode)
{
    ICOM_THIS (IGpgmeImpl,iface);

    fprintf (stderr,"*** " __PRETTY_FUNCTION__ "(%p)\n", This );

    return E_NOTIMPL;
}

#if 0
static HRESULT WINAPI
m_IGpgme_GetSigStatus(GpgmeCtx c, int idx,
                                  GpgmeSigStat *r_stat, time_t *r_created );
{
    return 0;
}


static HRESULT WINAPI
m_IGpgme_GetSigKey (GpgmeCtx c, int idx, GpgmeKey *r_key);
{
    return 0;
}

static HRESULT WINAPI
m_IGpgme_GetNotation(IGpgme *c, BSTR *retval)
{
    return 0;
}
#endif


static ICOM_VTABLE(IGpgme) igpgme_vtbl = 
{
    /* IUnknown methods */
    ICOM_MSVTABLE_COMPAT_DummyRTTIVALUE
    m_IGpgme_QueryInterface,
    m_IGpgme_AddRef,
    m_IGpgme_Release,
    /* IDispatch methods */
    m_stub_IDispatch_GetTypeInfoCount,
    m_stub_IDispatch_GetTypeInfo,
    m_stub_IDispatch_GetIDsOfNames,
    m_stub_IDispatch_Invoke,
    /* Our methods */
    m_IGpgme_GetVersion,
    m_IGpgme_GetEngineInfo,
    m_IGpgme_Cancel,             
    m_IGpgme_SetArmor,            
    m_IGpgme_GetArmor,            
    m_IGpgme_SetTextmode,         
    m_IGpgme_GetTextmode,         
    m_IGpgme_SetPlaintext,
    m_IGpgme_GetPlaintext,
    m_IGpgme_SetCiphertext,
    m_IGpgme_GetCiphertext,
    m_IGpgme_ClearRecipients,
    m_IGpgme_AddRecipient,
    m_IGpgme_ResetSignKeys,
    m_IGpgme_AddSignKey,
    m_IGpgme_Encrypt, 
    m_IGpgme_Sign, 
    m_IGpgme_SignEncrypt
};



/***************************************************************
 ******************  Gpgme Factory  ****************************
 ***************************************************************/

static HRESULT WINAPI 
m_GpgmeFactory_QueryInterface (IClassFactory *iface,
                               REFIID refiid, LPVOID *obj)
{
    ICOM_THIS (IClassFactoryImpl,iface);

    /*fprintf (stderr,"*** m_GpgmeFactory_QueryInterface(%p,%s)",
      This, debugstr_guid(refiid));*/
    if ( IsEqualGUID (&IID_IUnknown, refiid)
         || IsEqualGUID (&IID_IClassFactory, refiid) ) {
        *obj = This;
        /*fprintf (stderr," -> got %p\n", obj);*/
        return 0;
    }
    *obj = NULL;
    /*fprintf (stderr," -> none\n");*/
    return E_NOINTERFACE;
}

static ULONG WINAPI
m_GpgmeFactory_AddRef (IClassFactory *iface)
{
    ICOM_THIS(IClassFactoryImpl,iface);
    return ++(This->ref);
}

static ULONG WINAPI
m_GpgmeFactory_Release (IClassFactory *iface)
{
    ICOM_THIS(IClassFactoryImpl,iface);
    return --(This->ref);
}

static HRESULT WINAPI
m_GpgmeFactory_CreateInstance (IClassFactory *iface, IUnknown *outer,
                               REFIID refiid, LPVOID *r_obj )
{
    /*ICOM_THIS(IClassFactoryImpl,iface);*/

    fprintf (stderr,"*** m_GpgmeFactory_CreateInstance(%s)",
             debugstr_guid(refiid) );
    if (   IsEqualGUID (&IID_IUnknown, refiid)
        || IsEqualGUID (&IID_IGpgme, refiid) ) {
	IGpgmeImpl *obj;
        GpgmeCtx ctx;
        GpgmeError err;


        err = gpgme_new (&ctx);
        if (err) {
            fprintf (stderr," -> gpgme_new failed: %s\n", gpgme_strerror (err));
            return E_OUTOFMEMORY;
        }

	obj = HeapAlloc (GetProcessHeap(), 0, sizeof *obj );
	if ( !obj) {
            fprintf (stderr," -> out of core\n");
            gpgme_release (ctx);
            return E_OUTOFMEMORY;
        }
        memset (obj, 0, sizeof *obj);

	ICOM_VTBL(obj) = &igpgme_vtbl;
	obj->ref = 1;
        obj->mainctx = ctx;
        {   /* Fixme: need to release some stuff on error */
            HRESULT hr;
            ITypeLib *pTypeLib;

            hr = LoadRegTypeLib (&TLBID_Gpgcom, 1, 0, LANG_NEUTRAL, &pTypeLib);
            if (hr) {
                fprintf (stderr," -> LoadRegTypeLib failed: %lx\n", hr);
                return hr;
            }
            hr = ITypeLib_GetTypeInfoOfGuid (pTypeLib, &IID_IGpgme,
                                             &obj->std_disp.tinfo);
            ITypeLib_Release (pTypeLib);
            if (hr) {
                fprintf (stderr," -> GetTypeInfoOfGuid failed: %lx\n", hr);
                return hr;
            }
            hr = CreateStdDispatch ((IUnknown*)obj, obj, obj->std_disp.tinfo,
                                     &obj->std_disp.disp);
            if (hr) {
                fprintf (stderr," -> CreateStdDispatch failed: %lx\n", hr);
                return hr;
            }
        }

        CoAddRefServerProcess ();
        *r_obj = obj;
        fprintf (stderr," -> created %p\n", obj );
	return 0;
    }
    fprintf (stderr," -> no interface\n" );
    *r_obj = NULL;
    return E_NOINTERFACE;
}

static HRESULT WINAPI
m_GpgmeFactory_LockServer (IClassFactory *iface, BOOL dolock )
{
    if (dolock) {
        CoAddRefServerProcess ();
    }
    else {
        ULONG count = CoReleaseServerProcess ();
        if (!count && my_exit_event)
            SetEvent (my_exit_event);
    }
    return 0;
}

static ICOM_VTABLE(IClassFactory) igpgme_factory_vtbl = {
    ICOM_MSVTABLE_COMPAT_DummyRTTIVALUE
    m_GpgmeFactory_QueryInterface,
    m_GpgmeFactory_AddRef,
    m_GpgmeFactory_Release,
    m_GpgmeFactory_CreateInstance,
    m_GpgmeFactory_LockServer
};
static IClassFactoryImpl igpgme_CF = {&igpgme_factory_vtbl, 1 };

void
igpgme_register_exit_event (HANDLE ev)
{
    my_exit_event = ev;
}


IClassFactory *
igpgme_factory_new ( CLSID *r_clsid )
{
    *r_clsid = CLSID_Gpgme;
    IClassFactory_AddRef((IClassFactory*)&igpgme_CF);
    return (IClassFactory*)&igpgme_CF;
}

void
igpgme_factory_release ( IClassFactory *factory )
{
    /* it's static - nothing to do */
}

/* tgpgcom.c - Test the IGpgme classes
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

#define INITGUID
#include "igpgme.h"


int 
main (int argc, char **argv)
{
    IUnknown *pUnknown = NULL;
    IGpgme   *pGpgme;
    HRESULT hr;
    BSTR bs;
    
    hr = CoInitializeEx (NULL, COINIT_APARTMENTTHREADED); 
    if (hr)
        fprintf (stderr, "CoInitializeEx() failed: hr=%lu\n", hr);

    fprintf (stderr, "system initialized\n");
    hr = CoCreateInstance (&CLSID_Gpgme, NULL, CLSCTX_LOCAL_SERVER,
                           &IID_IUnknown, (void**)&pUnknown );
    if (hr)
        fprintf (stderr, "CoCreateInstance() failed: hr=%lx\n", hr);
    if (!pUnknown)
        exit (1);

    fprintf (stderr,"got object %p - querying %s\n",
             pUnknown, debugstr_guid(&IID_IGpgme));
    hr = IGpgme_QueryInterface (pUnknown, &IID_IGpgme, (void**)&pGpgme);
    if (hr) {
        fprintf (stderr, "QueryInterface() failed: hr=%lx\n", hr);
        goto leave;
    }
    fprintf (stderr, "got interface %p\n", pGpgme);

    hr = IGpgme_SetArmor (pGpgme, 1);
    fprintf (stderr, "SetArmor returned %lx\n", hr);

    hr = IGpgme_SetTextmode (pGpgme, 0);
    fprintf (stderr, "SetTextmode returned %lx\n", hr);

    hr = IGpgme_ClearRecipients (pGpgme);
    fprintf (stderr, "ClearRecipients returned %lx\n", hr);

    bs = SysAllocString (L"alice");
    if (!bs)
      fprintf (stderr, "SysAllocString failed: ec=%d\n", (int)GetLastError());
    else {
      int i;
      
      for (i=-4; i < 12; i++ )
        fprintf (stderr," %02X", ((unsigned char*)bs)[i] );
      putc ('\n', stderr);
    }
    hr = IGpgme_AddRecipient (pGpgme, bs, -1);
    fprintf (stderr, "AddRecipients returned %lx\n", hr);
    
    {
      SAFEARRAY *sa;
      VARIANT v;
      char *p;
      
      sa = SafeArrayCreateVector (VT_UI1, 0, 20);
      if (!sa) {
        fprintf (stderr, "SafeArrayCreateVector failed\n");
        goto leave;
      }

      hr = SafeArrayAccessData (sa, (void**)&p);
      if (hr) {
        fprintf (stderr,"SafeArrayAccessData failed: hr=%lx\n", hr);
        goto leave;
      }

      memcpy (p, "=> Omnis enim res <=", 20 );
      SafeArrayUnaccessData (sa);

      VariantInit (&v);
      v.vt = (VT_ARRAY|VT_UI1);
      v.u.parray = sa;
      
      hr = IGpgme_SetPlaintext (pGpgme, v );
      fprintf (stderr, "SetPlaintext returned %lx\n", hr);
      SafeArrayDestroyData (sa);
      SafeArrayDestroy (sa);

      VariantClear (&v);
    }

    hr = IGpgme_Encrypt (pGpgme);
    fprintf (stderr, "Encrypt returned %lx\n", hr);

    {
      VARIANT v;
    
      hr = IGpgme_GetCiphertext (pGpgme, &v);
      fprintf (stderr, "GetCiphertext returned %lx\n", hr);
      if (!hr) {
          if (v.vt != (VT_ARRAY|VT_UI1)) 
              fprintf (stderr, "Invalid array typed returned\n");
          else {
              unsigned char *p;
              
              hr = SafeArrayAccessData (v.u.parray, (void**)&p);
              if (hr) 
                  fprintf (stderr,"*** SafeArrayAccessData failed: %lx\n", hr);
              else {
                  size_t arraysize = v.u.parray->rgsabound[0].cElements;
                  fprintf (stderr,"*** got %d bytes\n", (int)arraysize);
                  for (;arraysize; arraysize--, p++ )
                      putc (*p, stderr);
                  SafeArrayUnaccessData (v.u.parray);
              }
          }
      }
    }
    IGpgme_Release (pGpgme);

 leave:
    CoUninitialize ();
    fprintf (stderr, "system uninitialized\n");
    return 0;
}
    






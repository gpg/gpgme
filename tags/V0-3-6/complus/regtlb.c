/* regtlb.c - Register a type library
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

#include "xmalloc.h"
#include "oleauto.h"

int 
main (int argc, char **argv)
{
    ITypeLib  *pTypeLib;
    wchar_t *fname;
    HRESULT hr;
    size_t n;

    if ( argc != 2 ) {
        fprintf (stderr,"usage: regtlb foo.tlb\n");
        return 1;
    }
    
    n = mbstowcs (NULL, argv[1], strlen(argv[1])+1);
    fprintf (stderr, "need %d bytes\n", (int)n);
    fname = xmalloc ((n+1)*sizeof *fname);
    mbstowcs (fname, argv[1], strlen (argv[1])+1);

    hr = CoInitializeEx (NULL, COINIT_MULTITHREADED); 
    if (hr)
        fprintf (stderr, "CoInitializeEx() failed: hr=%lu\n", hr);

    hr = LoadTypeLibEx (fname, REGKIND_REGISTER, &pTypeLib);
    if (hr)
        fprintf (stderr, "LoadTypeLibEx() failed: hr=%lx\n", hr);

    ITypeLib_Release (pTypeLib);

    CoUninitialize ();
    return 0;
}
    






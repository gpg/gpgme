/* w32-util.c - Utility functions for the W32 API
 *      Copyright (C) 1999 Free Software Foundation, Inc
 *	Copyright (C) 2001 Werner Koch (dd9jn)
 *      Copyright (C) 2001 g10 Code GmbH
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
#ifdef HAVE_DOSISH_SYSTEM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <windows.h>
#include "syshdr.h"

#include "util.h"

/****************
 * Return a string from the Win32 Registry or NULL in case of
 * error.  Caller must release the return value.   A NULL for root
 * is an alias fro HKEY_CURRENT_USER
 */
static char *
read_w32_registry_string ( const char *root,
                           const char *dir, const char *name )
{
    HKEY root_key, key_handle;
    DWORD n1, nbytes;
    char *result = NULL;

    if( !root )
        root_key = HKEY_CURRENT_USER;
    else if( !strcmp( root, "HKEY_CLASSES_ROOT" ) )
        root_key = HKEY_CLASSES_ROOT;
    else if( !strcmp( root, "HKEY_CURRENT_USER" ) )
        root_key = HKEY_CURRENT_USER;
    else if( !strcmp( root, "HKEY_LOCAL_MACHINE" ) )
        root_key = HKEY_LOCAL_MACHINE;
    else if( !strcmp( root, "HKEY_USERS" ) )
        root_key = HKEY_USERS;
    else if( !strcmp( root, "HKEY_PERFORMANCE_DATA" ) )
        root_key = HKEY_PERFORMANCE_DATA;
    else if( !strcmp( root, "HKEY_CURRENT_CONFIG" ) )
        root_key = HKEY_CURRENT_CONFIG;
    else
        return NULL;

    if( RegOpenKeyEx( root_key, dir, 0, KEY_READ, &key_handle ) )
        return NULL; /* no need for a RegClose, so return direct */

    nbytes = 1;
    if( RegQueryValueEx( key_handle, name, 0, NULL, NULL, &nbytes ) )
        goto leave;
    result = xtrymalloc( (n1=nbytes+1) );
    if( !result )
        goto leave;
    if( RegQueryValueEx( key_handle, name, 0, NULL, result, &n1 ) ) {
        xfree(result); result = NULL;
        goto leave;
    }
    result[nbytes] = 0; /* make sure it is really a string  */

  leave:
    RegCloseKey( key_handle );
    return result;
}


const char *
_gpgme_get_gpg_path (void)
{
    static char *gpg_program = NULL;
    
    if (!gpg_program) {
        gpg_program = read_w32_registry_string ( NULL,
                                  "Software\\GNU\\GnuPG", "gpgProgram" );
        if (gpg_program) {
            int i;
            
            DEBUG1 ("found gpgProgram in registry: `%s'", gpg_program );
            for (i=0; gpg_program[i]; i++) {
                if (gpg_program[i] == '/')
                    gpg_program[i] = '\\';
            }
        }
        else {
            gpg_program = GPG_PATH;
        }
    }
    
    return gpg_program;
}




#endif /*HAVE_DOSISH_SYSTEM*/






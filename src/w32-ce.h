/* w32-ce.h 
   Copyright (C) 2010 g10 Code GmbH

   This file is part of GPGME.
 
   GPGME is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
   
   GPGME is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
   
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef GPGME_W32_CE_H
#define GPGME_W32_CE_H

#include <time.h>
#include <stdarg.h>

/* For getaddrinfo.  */
#define _MSV_VER 0x401
#include <windows.h>


/* shlobj.h declares these only for _WIN32_IE that we don't want to define.
   In any case, with mingw32ce we only get a SHGetSpecialFolderPath.  */
#define SHGetSpecialFolderPathW SHGetSpecialFolderPath
BOOL WINAPI SHGetSpecialFolderPathA(HWND,LPSTR,int,BOOL);
BOOL WINAPI SHGetSpecialFolderPathW(HWND,LPWSTR,int,BOOL);


#define getenv _gpgme_wince_getenv
char *getenv (const char *name);

#include <io.h>
#define isatty(fd) 0


/* Windows CE is missing some Windows functions that we want.  */

#define GetSystemTimeAsFileTime _gpgme_wince_GetSystemTimeAsFileTime
void GetSystemTimeAsFileTime (LPFILETIME ftp);

#define DeleteFileA _gpgme_wince_DeleteFileA
BOOL DeleteFileA(LPCSTR);

#define CreateProcessA _gpgme_wince_CreateProcessA
BOOL CreateProcessA(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,PVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);

#define RegOpenKeyExA _gpgme_wince_RegOpenKeyExA
LONG RegOpenKeyExA(HKEY,LPCSTR,DWORD,REGSAM,PHKEY);

#define RegQueryValueExA _gpgme_wince_RegQueryValueExA
LONG WINAPI RegQueryValueExA(HKEY,LPCSTR,LPDWORD,LPDWORD,LPBYTE,LPDWORD);

#define GetTempPathA _gpgme_wince_GetTempPathA
DWORD GetTempPathA(DWORD,LPSTR);

#define SHGetSpecialFolderPathA _gpgme_wince_SHGetSpecialFolderPathA
BOOL SHGetSpecialFolderPathA(HWND,LPSTR,int,BOOL);


#endif /* GPGME_W32_CE_H */

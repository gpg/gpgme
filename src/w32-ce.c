/* w32-ce.h
   Copyright (C) 2010 g10 Code GmbH
   Copyright (C) 1991,92,97,2000,02 Free Software Foundation, Inc.

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
   License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <errno.h>
#include <assert.h>

#include <gpg-error.h>

#define _WIN32_IE 0x0400 /* Required for SHGetSpecialFolderPathW.  */

/* We need to include the windows stuff here prior to shlobj.h so that
   we get the right winsock version.  This is usually done in w32-ce.h
   but that header also redefines some Windows functions which we need
   to avoid unless having included shlobj.h.  */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>

#include "w32-ce.h"

/* Return a malloced string encoded in UTF-8 from the wide char input
   string STRING.  Caller must free this value.  Returns NULL and sets
   ERRNO on failure.  Calling this function with STRING set to NULL is
   not defined.  */
char *
wchar_to_utf8 (const wchar_t *string)
{
  int n;
  char *result;

  n = WideCharToMultiByte (CP_UTF8, 0, string, -1, NULL, 0, NULL, NULL);
  if (n < 0)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  result = malloc (n+1);
  if (!result)
    return NULL;

  n = WideCharToMultiByte (CP_UTF8, 0, string, -1, result, n, NULL, NULL);
  if (n < 0)
    {
      free (result);
      gpg_err_set_errno (EINVAL);
      result = NULL;
    }
  return result;
}


/* Return a malloced wide char string from an UTF-8 encoded input
   string STRING.  Caller must free this value.  Returns NULL and sets
   ERRNO on failure.  Calling this function with STRING set to NULL is
   not defined.  */
wchar_t *
utf8_to_wchar (const char *string)
{
  int n;
  size_t nbytes;
  wchar_t *result;

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, NULL, 0);
  if (n < 0)
    {
      gpg_err_set_errno (EINVAL);
      return NULL;
    }

  nbytes = (size_t)(n+1) * sizeof(*result);
  if (nbytes / sizeof(*result) != (n+1))
    {
      gpg_err_set_errno (ENOMEM);
      return NULL;
    }
  result = malloc (nbytes);
  if (!result)
    return NULL;

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, result, n);
  if (n < 0)
    {
      free (result);
      gpg_err_set_errno (EINVAL);
      result = NULL;
    }
  return result;
}


#define MAX_ENV 30

char *environ[MAX_ENV + 1];

char *
getenv (const char *name)
{
  static char *past_result;
  char **envp;

  if (past_result)
    {
      free (past_result);
      past_result = NULL;
    }

#if 0
  if (! strcmp (name, "DBUS_VERBOSE"))
    return past_result = get_verbose_setting ();
  else if (! strcmp (name, "HOMEPATH"))
    return past_result = find_my_documents_folder ();
  else if (! strcmp (name, "DBUS_DATADIR"))
    return past_result = find_inst_subdir ("share");
#endif

  for (envp = environ; *envp != 0; envp++)
    {
      const char *varp = name;
      char *ep = *envp;

      while (*varp == *ep && *varp != '\0')
	{
	  ++ep;
	  ++varp;
	};

      if (*varp == '\0' && *ep == '=')
	return ep + 1;
    }

  return NULL;
}


void
GetSystemTimeAsFileTime (LPFILETIME ftp)
{
  SYSTEMTIME st;
  GetSystemTime (&st);
  SystemTimeToFileTime (&st, ftp);
}


BOOL
DeleteFileA (LPCSTR lpFileName)
{
  wchar_t *filename;
  BOOL result;
  int err;

  filename = utf8_to_wchar (lpFileName);
  if (!filename)
    return FALSE;

  result = DeleteFileW (filename);

  err = GetLastError ();
  free (filename);
  SetLastError (err);
  return result;
}


HANDLE
CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwSharedMode,
	     LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	     DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
	     HANDLE hTemplateFile)
{
  wchar_t *filename;
  HANDLE result;
  int err;

  filename = utf8_to_wchar (lpFileName);
  if (!filename)
    return INVALID_HANDLE_VALUE;

  result = CreateFileW (filename, dwDesiredAccess, dwSharedMode,
			lpSecurityAttributes, dwCreationDisposition,
			dwFlagsAndAttributes, hTemplateFile);

  err = GetLastError ();
  free (filename);
  SetLastError (err);
  return result;
}


BOOL
CreateProcessA (LPCSTR pszImageName, LPSTR pszCmdLine,
                LPSECURITY_ATTRIBUTES psaProcess,
                LPSECURITY_ATTRIBUTES psaThread, BOOL fInheritHandles,
                DWORD fdwCreate, PVOID pvEnvironment, LPCSTR pszCurDir,
                LPSTARTUPINFOA psiStartInfo,
                LPPROCESS_INFORMATION pProcInfo)
{
  wchar_t *image_name = NULL;
  wchar_t *cmd_line = NULL;
  BOOL result;
  int err;

  assert (psaProcess == NULL);
  assert (psaThread == NULL);
  assert (fInheritHandles == FALSE);
  assert (pvEnvironment == NULL);
  assert (pszCurDir == NULL);
  /* psiStartInfo is generally not NULL.  */

  if (pszImageName)
    {
      image_name = utf8_to_wchar (pszImageName);
      if (!image_name)
	return 0;
    }
  if (pszCmdLine)
    {
      cmd_line = utf8_to_wchar (pszCmdLine);
      if (!cmd_line)
        {
          if (image_name)
            free (image_name);
          return 0;
        }
    }

  result = CreateProcessW (image_name, cmd_line, NULL, NULL, FALSE,
                           fdwCreate, NULL, NULL, NULL, pProcInfo);

  err = GetLastError ();
  free (image_name);
  free (cmd_line);
  SetLastError (err);
  return result;
}


LONG
RegOpenKeyExA (HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
               REGSAM samDesired, PHKEY phkResult)
{
  wchar_t *subkey;
  LONG result;
  int err;

  if (lpSubKey)
    {
      subkey = utf8_to_wchar (lpSubKey);
      if (!subkey)
	return 0;
    }
  else
    subkey = NULL;

  result = RegOpenKeyEx (hKey, subkey, ulOptions, samDesired, phkResult);

  err = GetLastError ();
  free (subkey);
  SetLastError (err);
  return result;
}


LONG WINAPI
RegQueryValueExA (HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
                  LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
  wchar_t *name;
  LONG err;
  void *data;
  DWORD data_len;
  DWORD type;

  if (lpValueName)
    {
      name = utf8_to_wchar (lpValueName);
      if (!name)
	return GetLastError ();
    }
  else
    name = NULL;

  data_len = 0;
  err = RegQueryValueExW (hKey, name, lpReserved, lpType, NULL, &data_len);
  if (err || !lpcbData)
    {
      free (name);
      return err;
    }

  data = malloc (data_len + sizeof (wchar_t));
  if (!data)
    {
      free (name);
      return ERROR_NOT_ENOUGH_MEMORY;
    }

  err = RegQueryValueExW (hKey, name, lpReserved, &type, data, &data_len);
  if (lpType)
    *lpType = type;
  free (name);
  /* If err is ERROR_MORE_DATA, there probably was a race condition.
     We can punt this to the caller just as well.  */
  if (err)
    return err;

  /* NOTE: REG_MULTI_SZ and REG_EXPAND_SZ not supported, because they
     are not needed in this module.  */
  if (type == REG_SZ)
    {
      char *data_c;
      int data_c_len;

      /* This is valid since we allocated one more above.  */
      ((char*)data)[data_len] = '\0';
      ((char*)data)[data_len + 1] = '\0';

      data_c = wchar_to_utf8 ((wchar_t*) data);
      if (!data_c)
        return GetLastError();

      data_c_len = strlen (data_c) + 1;
      assert (data_c_len <= data_len + sizeof (wchar_t));
      memcpy (data, data_c, data_c_len);
      data_len = data_c_len;
      free (data_c);
    }

  /* DATA and DATA_LEN now contain the result.  */
  if (lpData)
    {
      if (data_len > *lpcbData)
        err = ERROR_MORE_DATA;
      else
        memcpy (lpData, data, data_len);
    }
  *lpcbData = data_len;
  return err;
}


DWORD
GetTempPathA (DWORD nBufferLength, LPSTR lpBuffer)
{
  wchar_t dummy[1];
  DWORD len;

  len = GetTempPathW (0, dummy);
  if (len == 0)
    return 0;

  assert (len <= MAX_PATH);

  /* Better be safe than sorry.  MSDN doesn't say if len is with or
     without terminating 0.  */
  len++;

  {
    wchar_t *buffer_w;
    DWORD len_w;
    char *buffer_c;
    DWORD len_c;

    buffer_w = malloc (sizeof (wchar_t) * len);
    if (! buffer_w)
      return 0;

    len_w = GetTempPathW (len, buffer_w);
    /* Give up if we still can't get at it.  */
    if (len_w == 0 || len_w >= len)
      {
        free (buffer_w);
        return 0;
      }

    /* Better be really safe.  */
    buffer_w[len_w] = '\0';

    buffer_c = wchar_to_utf8 (buffer_w);
    free (buffer_w);
    if (! buffer_c)
      return 0;

    /* strlen is correct (not _mbstrlen), because we want storage and
       not string length.  */
    len_c = strlen (buffer_c) + 1;
    if (len_c > nBufferLength)
      return len_c;

    strcpy (lpBuffer, buffer_c);
    free (buffer_c);
    return len_c - 1;
  }
}


/* The symbol is named SHGetSpecialFolderPath and not
   SHGetSpecialFolderPathW but shlobj.h from cegcc redefines it to *W
   which is a bug.  Work around it.  */
#ifdef __MINGW32CE__
# undef SHGetSpecialFolderPath
#endif
BOOL
SHGetSpecialFolderPathA (HWND hwndOwner, LPSTR lpszPath, int nFolder,
                         BOOL fCreate)
{
  wchar_t path[MAX_PATH];
  char *path_c;
  BOOL result;

  path[0] = (wchar_t) 0;
  result = SHGetSpecialFolderPath (hwndOwner, path, nFolder, fCreate);
  /* Note: May return false even if succeeds.  */

  path[MAX_PATH - 1] = (wchar_t) 0;
  path_c = wchar_to_utf8 (path);
  if (! path_c)
    return 0;

  strncpy (lpszPath, path_c, MAX_PATH);
  free (path_c);
  lpszPath[MAX_PATH - 1] = '\0';
  return result;
}

/* Replacement for the access function.  Note that we can't use fopen
   here because wince might now allow to have a shared read for an
   executable; it is better to to read the file attributes.

   Limitation:  Only F_OK is supported.
*/
int
_gpgme_wince_access (const char *fname, int mode)
{
  DWORD attr;
  wchar_t *wfname;

  (void)mode;

  wfname = utf8_to_wchar (fname);
  if (!wfname)
    return -1;

  attr = GetFileAttributes (wfname);
  free (wfname);
  if (attr == (DWORD)(-1))
    {
      gpg_err_set_errno (ENOENT);
      return -1;
    }
  return 0;
}


/* Perform a binary search for KEY in BASE which has NMEMB elements
   of SIZE bytes each.  The comparisons are done by (*COMPAR)().
   Code taken from glibc-2.6. */
void *
_gpgme_wince_bsearch (const void *key, const void *base,
                      size_t nmemb, size_t size,
                      int (*compar) (const void *, const void *))
{
  size_t l, u, idx;
  const void *p;
  int comparison;

  l = 0;
  u = nmemb;
  while (l < u)
    {
      idx = (l + u) / 2;
      p = (void *) (((const char *) base) + (idx * size));
      comparison = (*compar) (key, p);
      if (comparison < 0)
	u = idx;
      else if (comparison > 0)
	l = idx + 1;
      else
	return (void *) p;
    }

  return NULL;
}


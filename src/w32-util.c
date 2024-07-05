/* w32-util.c - Utility functions for the W32 API
 * Copyright (C) 1999 Free Software Foundation, Inc
 * Copyright (C) 2001 Werner Koch (dd9jn)
 * Copyright (C) 2001, 2002, 2003, 2004, 2007, 2013 g10 Code GmbH
 *
 * This file is part of GPGME.
 *
 * GPGME is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GPGME is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <fcntl.h>
#include <io.h>

#if __MINGW64_VERSION_MAJOR >= 2
# define _WIN32_IE 0x0501 /* Required by mingw64 toolkit.  */
#else
# define _WIN32_IE 0x0400 /* Required for SHGetSpecialFolderPathA.  */
#endif

/* We need to include the windows stuff here prior to shlobj.h so that
   we get the right winsock version.  This is usually done in util.h
   but that header also redefines some Windows functions which we need
   to avoid unless having included shlobj.h.  */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>

#include "util.h"
#include "sema.h"
#include "debug.h"
#include "sys-util.h"


#define HAVE_ALLOW_SET_FOREGROUND_WINDOW 1
#ifndef F_OK
# define F_OK 0
#endif

/* The Registry key used by GNUPG.  */
#ifdef _WIN64
# define GNUPG_REGKEY_2  "Software\\Wow6432Node\\GNU\\GnuPG"
#else
# define GNUPG_REGKEY_2  "Software\\GNU\\GnuPG"
#endif
#ifdef _WIN64
# define GNUPG_REGKEY_3  "Software\\Wow6432Node\\GnuPG"
#else
# define GNUPG_REGKEY_3  "Software\\GnuPG"
#endif

/* Installation type constants.  */
#define INST_TYPE_GPG4WIN  1
#define INST_TYPE_GPGDESK  2

/* Relative name parts for different installation types.  */
#define INST_TYPE_GPG4WIN_DIR "\\..\\..\\GnuPG\\bin"
#define INST_TYPE_GPGDESK_DIR "\\..\\GnuPG\\bin"




DEFINE_STATIC_LOCK (get_path_lock);

/* The module handle of this DLL.  If we are linked statically,
   dllmain does not exist and thus the value of my_hmodule will be
   NULL.  The effect is that a GetModuleFileName always returns the
   file name of the DLL or executable which contains the gpgme code.  */
static HMODULE my_hmodule;

/* These variables store the malloced name of alternative default
   binaries.  They are set only once by gpgme_set_global_flag.  */
static char *default_gpg_name;
static char *default_gpgconf_name;
/* If this variable is not NULL the value is assumed to be the
   installation directory.  The variable may only be set once by
   gpgme_set_global_flag and accessed by _gpgme_get_inst_dir.  */
static char *override_inst_dir;

#define RTLD_LAZY 0

static GPG_ERR_INLINE void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);

  (void)flag;
  return hd;
}

static GPG_ERR_INLINE void *
dlsym (void * hd, const char * sym)
{
  if (hd && sym)
    {
      void * fnc = GetProcAddress (hd, sym);
      if (!fnc)
        return NULL;
      return fnc;
    }
  return NULL;
}

static GPG_ERR_INLINE int
dlclose (void * hd)
{
  if (hd)
    {
      FreeLibrary (hd);
      return 0;
    }
  return -1;
}


/* Return a malloced string encoded in UTF-8 from the wide char input
   string STRING.  Caller must free this value.  Returns NULL and sets
   ERRNO on failure.  Calling this function with STRING set to NULL is
   not defined.  */
static char *
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


/* Return a malloced wide char string from a UTF-8 encoded input
   string STRING.  Caller must free this value. On failure returns
   NULL; caller may use GetLastError to get the actual error number.
   Calling this function with STRING set to NULL is not defined. */
static wchar_t *
utf8_to_wchar (const char *string)
{
  int n;
  wchar_t *result;


  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, NULL, 0);
  if (n < 0)
    return NULL;

  result = (wchar_t *) malloc ((n+1) * sizeof *result);
  if (!result)
    return NULL;

  n = MultiByteToWideChar (CP_UTF8, 0, string, -1, result, n);
  if (n < 0)
    {
      free (result);
      return NULL;
    }
  return result;
}


/* Same as utf8_to_wchar but calling it with NULL returns
   NULL.  So a return value of NULL only indicates failure
   if STRING is not set to NULL. */
static wchar_t *
utf8_to_wchar0 (const char *string)
{
  if (!string)
    return NULL;

  return utf8_to_wchar (string);
}


/* Replace all forward slashes by backslashes.  */
static void
replace_slashes (char *string)
{
  for (; *string; string++)
    if (*string == '/')
      *string = '\\';
}


/* Get the base name of NAME.  Returns a pointer into NAME right after
   the last slash or backslash or to NAME if no slash or backslash
   exists.  */
static const char *
get_basename (const char *name)
{
  const char *mark, *s;

  for (mark=NULL, s=name; *s; s++)
    if (*s == '/' || *s == '\\')
      mark = s;

  return mark? mark+1 : name;
}


void
_gpgme_allow_set_foreground_window (pid_t pid)
{
#ifdef HAVE_ALLOW_SET_FOREGROUND_WINDOW
  static int initialized;
  static BOOL (WINAPI * func)(DWORD);
  void *handle;

  if (!initialized)
    {
      /* Available since W2000; thus we dynload it.  */
      initialized = 1;
      handle = dlopen ("user32.dll", RTLD_LAZY);
      if (handle)
        {
          func = dlsym (handle, "AllowSetForegroundWindow");
          if (!func)
            {
              dlclose (handle);
              handle = NULL;
            }
        }
    }

  if (!pid || pid == (pid_t)(-1))
    {
      TRACE (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", NULL,
	      "no action for pid %d", (int)pid);
    }
  else if (func)
    {
      int rc = func (pid);
      TRACE (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", NULL,
	      "called for pid %d; result=%d", (int)pid, rc);

    }
  else
    {
      TRACE (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", NULL,
	      "function not available");
    }
#endif /* HAVE_ALLOW_SET_FOREGROUND_WINDOW */
}


/* Wrapper around CancelSynchronousIo which is only available since
 * Vista.  */
void
_gpgme_w32_cancel_synchronous_io (HANDLE thread)
{
  static int initialized;
  static BOOL (WINAPI * func)(HANDLE);
  void *handle;

  if (!initialized)
    {
      /* Available since Vista; thus we dynload it.  */
      initialized = 1;
      handle = dlopen ("kernel32.dll", RTLD_LAZY);
      if (handle)
        {
          func = dlsym (handle, "CancelSynchronousIo");
          if (!func)
            {
              dlclose (handle);
              handle = NULL;
            }
        }
    }

  if (func)
    {
      if (!func (thread) && GetLastError() != ERROR_NOT_FOUND)
        {
          TRACE (DEBUG_ENGINE, "gpgme:CancelSynchronousIo", NULL,
                 "called for thread %p: ec=%u",
                 thread, (unsigned int)GetLastError ());
        }
    }
  else
    {
      TRACE (DEBUG_ENGINE, "gpgme:CancelSynchronousIo", NULL,
	      "function not available");
    }
}


/* Return a string from the W32 Registry or NULL in case of error.
   Caller must release the return value.  A NULL for root is an alias
   for HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE in turn. */
static char *
read_w32_registry_string (const char *root, const char *dir, const char *name)
{
  HKEY root_key, key_handle;
  DWORD n1, nbytes, type;
  char *result = NULL;

  if (!root)
    root_key = HKEY_CURRENT_USER;
  else if (!strcmp( root, "HKEY_CLASSES_ROOT"))
    root_key = HKEY_CLASSES_ROOT;
  else if (!strcmp( root, "HKEY_CURRENT_USER"))
    root_key = HKEY_CURRENT_USER;
  else if (!strcmp( root, "HKEY_LOCAL_MACHINE"))
    root_key = HKEY_LOCAL_MACHINE;
  else if (!strcmp( root, "HKEY_USERS"))
    root_key = HKEY_USERS;
  else if (!strcmp( root, "HKEY_PERFORMANCE_DATA"))
    root_key = HKEY_PERFORMANCE_DATA;
  else if (!strcmp( root, "HKEY_CURRENT_CONFIG"))
    root_key = HKEY_CURRENT_CONFIG;
  else
    return NULL;

  if (RegOpenKeyExA (root_key, dir, 0, KEY_READ, &key_handle))
    {
      if (root)
        return NULL; /* no need for a RegClose, so return direct */
      /* It seems to be common practise to fall back to HKLM. */
      if (RegOpenKeyExA (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle))
        return NULL; /* still no need for a RegClose, so return direct */
    }

  nbytes = 1;
  if (RegQueryValueExA (key_handle, name, 0, NULL, NULL, &nbytes))
    {
      if (root)
        goto leave;
      /* Try to fallback to HKLM also vor a missing value.  */
      RegCloseKey (key_handle);
      if (RegOpenKeyExA (HKEY_LOCAL_MACHINE, dir, 0, KEY_READ, &key_handle))
        return NULL; /* Nope.  */
      if (RegQueryValueExA (key_handle, name, 0, NULL, NULL, &nbytes))
        goto leave;
    }
  n1 = nbytes + 1;
  result = malloc (n1);
  if (!result)
    goto leave;
  if (RegQueryValueExA (key_handle, name, 0, &type, (LPBYTE) result, &n1))
    {
      free (result);
      result = NULL;
      goto leave;
    }
  result[nbytes] = 0; /* Make sure it is really a string.  */

 leave:
  RegCloseKey (key_handle);
  return result;
}


/* Return the name of the directory with the gpgme DLL or the EXE (if
   statically linked).  May return NULL on severe errors. */
const char *
_gpgme_get_inst_dir (void)
{
  static char *inst_dir;

  if (override_inst_dir)
    return override_inst_dir;

  LOCK (get_path_lock);
  if (!inst_dir)
    {
      wchar_t *moddir;

      moddir = malloc ((MAX_PATH+5) * sizeof *moddir);
      if (moddir)
        {
          if (!GetModuleFileNameW (my_hmodule, moddir, MAX_PATH))
            *moddir = 0;
          if (!*moddir)
            gpg_err_set_errno (ENOENT);
          else
            {
              inst_dir = wchar_to_utf8 (moddir);
              if (inst_dir)
                {
                  char *p = strrchr (inst_dir, '\\');
                  if (p)
                    *p = 0;
                }
            }
          free (moddir);
        }
    }
  UNLOCK (get_path_lock);
  return inst_dir;
}


static char *
find_program_in_dir (const char *dir, const char *name)
{
  char *result;

  result = _gpgme_strconcat (dir, "\\", name, NULL);
  if (!result)
    return NULL;

  if (_gpgme_access (result, F_OK))
    {
      free (result);
      return NULL;
    }

  return result;
}


static char *
find_program_at_standard_place (const char *name)
{
  wchar_t path[MAX_PATH];
  char *result = NULL;

  /* See https://wiki.tcl-lang.org/page/Getting+Windows+%22special+folders%22+with+Ffidl for details on compatibility.

     We First try the generic place and then fallback to the x86
     (i.e. 32 bit) place.  This will prefer a 64 bit of the program
     over a 32 bit version on 64 bit Windows if installed.  */
  if (SHGetSpecialFolderPathW (NULL, path, CSIDL_PROGRAM_FILES, 0))
    {
      char *utf8_path = wchar_to_utf8 (path);
      result = _gpgme_strconcat (utf8_path, "\\", name, NULL);
      free (utf8_path);
      if (result && _gpgme_access (result, F_OK))
        {
          free (result);
          result = NULL;
        }
    }
  if (!result
      && SHGetSpecialFolderPathW (NULL, path, CSIDL_PROGRAM_FILESX86, 0))
    {
      char *utf8_path = wchar_to_utf8 (path);
      result = _gpgme_strconcat (utf8_path, "\\", name, NULL);
      free (utf8_path);
      if (result && _gpgme_access (result, F_OK))
        {
          free (result);
          result = NULL;
        }
    }
  return result;
}


/* Set the default name for the gpg binary.  This function may only be
   called by gpgme_set_global_flag.  Returns 0 on success.  */
int
_gpgme_set_default_gpg_name (const char *name)
{
  if (!default_gpg_name)
    {
      default_gpg_name = _gpgme_strconcat (name, ".exe", NULL);
      if (default_gpg_name)
        replace_slashes (default_gpg_name);
    }
  return !default_gpg_name;
}

/* Set the default name for the gpgconf binary.  This function may only be
   called by gpgme_set_global_flag.  Returns 0 on success.  */
int
_gpgme_set_default_gpgconf_name (const char *name)
{
  if (!default_gpgconf_name)
    {
      default_gpgconf_name = _gpgme_strconcat (name, ".exe", NULL);
      if (default_gpgconf_name)
        replace_slashes (default_gpgconf_name);
    }
  return !default_gpgconf_name;
}


/* Set the override installation directory.  This function may only be
   called by gpgme_set_global_flag.  Returns 0 on success.  */
int
_gpgme_set_override_inst_dir (const char *dir)
{
  if (!override_inst_dir)
    {
      override_inst_dir = strdup (dir);
      if (override_inst_dir)
        {
          replace_slashes (override_inst_dir);
          /* Remove a trailing slash.  */
          if (*override_inst_dir
              && override_inst_dir[strlen (override_inst_dir)-1] == '\\')
            override_inst_dir[strlen (override_inst_dir)-1] = 0;
        }
    }
  return !override_inst_dir;
}


/* Used by gpgme_set_global_flag to set the installation type.
 * VALUE is a string interpreted as integer with this meaning:
 *   0 = standard
 *   1 = Gpg4win 4 style (INST_TYPE_GPG4WIN)
 *   2 = GnuPG (VS-)Desktop style (INST_TYPE_GPGDESK)
 * If VALUE is NULL, nothing is changed.  The return value is the
 * previous value.
 */
int
_gpgme_set_get_inst_type (const char *value)
{
  static int inst_type;
  int previous_type;

  previous_type = inst_type;
  if (value)
    inst_type = atoi (value);
  return previous_type;
}


/* Return the full file name of the GPG binary.  This function is used
   iff gpgconf was not found and thus it can be assumed that gpg2 is
   not installed.  This function is only called by get_gpgconf_item
   and may not be called concurrently. */
char *
_gpgme_get_gpg_path (void)
{
  char *gpg = NULL;
  const char *name, *inst_dir;

  name = default_gpg_name? get_basename (default_gpg_name) : "gpg.exe";

  /* 1. Try to find gpg.exe in the installation directory of gpgme.  */
  inst_dir = _gpgme_get_inst_dir ();
  if (inst_dir)
    {
      gpg = find_program_in_dir (inst_dir, name);
    }

  /* 2. Try to find gpg.exe using that ancient registry key.  */
  if (!gpg)
    {
      char *dir;

      dir = read_w32_registry_string ("HKEY_LOCAL_MACHINE",
                                      GNUPG_REGKEY_2,
                                      "Install Directory");
      if (dir)
        {
          gpg = find_program_in_dir (dir, name);
          free (dir);
        }
    }

  /* 3. Try to find gpg.exe below CSIDL_PROGRAM_FILES.  */
  if (!gpg)
    {
      name = default_gpg_name? default_gpg_name : "GNU\\GnuPG\\gpg.exe";
      gpg = find_program_at_standard_place (name);
    }

  /* 4. Print a debug message if not found.  */
  if (!gpg)
    _gpgme_debug (NULL, DEBUG_ENGINE, -1, NULL, NULL, NULL,
                  "_gpgme_get_gpg_path: '%s' not found", name);

  return gpg;
}


/* Helper for _gpgme_get_gpgconf_path.  */
static char *
find_version_file (const char *inst_dir)
{
  char *fname;

  fname = _gpgme_strconcat (inst_dir, "\\..\\", "VERSION.sig", NULL);
  if (fname && !_gpgme_access (fname, F_OK))
    {
      fname[strlen(fname)-4] = 0;
      if (!_gpgme_access (fname, F_OK))
        return fname;
    }
  free (fname);
  /* Check the case that a binary in gnupg/bin uses libgpgme.  */
  fname = _gpgme_strconcat (inst_dir, "\\..\\..\\", "VERSION.sig", NULL);
  if (fname && !_gpgme_access (fname, F_OK))
    {
      fname[strlen(fname)-4] = 0;
      if (!_gpgme_access (fname, F_OK))
        return fname;
    }
  free (fname);
  return NULL;
}


/* This function is only called by get_gpgconf_item and may not be
   called concurrently.  */
char *
_gpgme_get_gpgconf_path (void)
{
  char *gpgconf = NULL;
  const char *inst_dir, *name;
  int inst_type;
  char *dir = NULL;

  name = default_gpgconf_name? get_basename(default_gpgconf_name):"gpgconf.exe";

  inst_dir = _gpgme_get_inst_dir ();
  inst_type = _gpgme_set_get_inst_type (NULL);

  /* 0.0. If no installation type has been explicitly requested guess
   * one by looking at files used by the installation type.  */
  if (inst_dir && !inst_type)
    {
      gpgrt_stream_t fp;
      char buffer[128];
      int n;

      free (dir);
      dir = find_version_file (inst_dir);
      if (dir && (fp = gpgrt_fopen (dir, "r")))
        {
          n = gpgrt_fread (buffer, 1, 128, fp);
          if (n > 10)
            {
              buffer[n-1] = 0;
              if (strstr (buffer, "GnuPG") && strstr (buffer, "Desktop"))
                inst_type = INST_TYPE_GPGDESK;
            }
          gpgrt_fclose (fp);
        }
    }

  /* 0.1. If an installation type was requested or guessed try to find
   * gpgconf.exe depending on that installation type.  */
  if (inst_dir
      && (inst_type == INST_TYPE_GPG4WIN || inst_type == INST_TYPE_GPGDESK))
    {
      free (dir);
      dir = _gpgme_strconcat
        (inst_dir,
         inst_type == INST_TYPE_GPG4WIN? INST_TYPE_GPG4WIN_DIR
         /*                         */ : INST_TYPE_GPGDESK_DIR,
         NULL);
      gpgconf = find_program_in_dir (dir, name);
    }

  /* 1. Try to find gpgconf.exe in the installation directory of gpgme.  */
  if (!gpgconf && inst_dir)
    {
      gpgconf = find_program_in_dir (inst_dir, name);
    }

  /* 2. Try to find gpgconf.exe from GnuPG >= 2.1 below CSIDL_PROGRAM_FILES. */
  if (!gpgconf)
    {
      const char *name2 = (default_gpgconf_name ? default_gpgconf_name
                           /**/                 : "GnuPG\\bin\\gpgconf.exe");
      gpgconf = find_program_at_standard_place (name2);
    }

  /* 3. Try to find gpgconf.exe using the Windows registry. */
  if (!gpgconf)
    {
      free (dir);
      dir = read_w32_registry_string (NULL,
                                      GNUPG_REGKEY_2,
                                      "Install Directory");
      if (!dir)
        {
          char *tmp = read_w32_registry_string (NULL,
                                                GNUPG_REGKEY_3,
                                                "Install Directory");
          if (tmp)
            {
              dir = _gpgme_strconcat (tmp, "\\bin", NULL);
              free (tmp);
              if (!dir)
                return NULL;
            }
        }
      if (dir)
        gpgconf = find_program_in_dir (dir, name);
    }

  /* 4. Try to find gpgconf.exe from Gpg4win below CSIDL_PROGRAM_FILES.  */
  if (!gpgconf)
    {
      gpgconf = find_program_at_standard_place ("GNU\\GnuPG\\gpgconf.exe");
    }

  /* 5. Try to find gpgconf.exe relative to us as Gpg4win installs it.  */
  if (!gpgconf && inst_dir)
    {
      free (dir);
      dir = _gpgme_strconcat (inst_dir, INST_TYPE_GPG4WIN_DIR, NULL);
      gpgconf = find_program_in_dir (dir, name);
    }

  /* 6. Try to find gpgconf.exe relative to us as GnuPG VSD installs it. */
  if (!gpgconf && inst_dir)
    {
      free (dir);
      dir = _gpgme_strconcat (inst_dir, INST_TYPE_GPGDESK_DIR, NULL);
      gpgconf = find_program_in_dir (dir, name);
    }

  /* Print a debug message if not found.  */
  if (!gpgconf)
    _gpgme_debug (NULL, DEBUG_ENGINE, -1, NULL, NULL, NULL,
                  "_gpgme_get_gpgconf_path: '%s' not found",name);

  free (dir);
  return gpgconf;
}


const char *
_gpgme_get_w32spawn_path (void)
{
  static char *w32spawn_program;
  const char *inst_dir;

  inst_dir = _gpgme_get_inst_dir ();
  LOCK (get_path_lock);
  if (!w32spawn_program)
    w32spawn_program = find_program_in_dir (inst_dir, "gpgme-w32spawn.exe");
  UNLOCK (get_path_lock);
  return w32spawn_program;
}


/* Return an integer value from gpgme specific configuration
   entries. VALUE receives that value; function returns true if a value
   has been configured and false if not. */
int
_gpgme_get_conf_int (const char *key, int *value)
{
  char *tmp = read_w32_registry_string (NULL, "Software\\GNU\\gpgme", key);
  if (!tmp)
    return 0;
  *value = atoi (tmp);
  free (tmp);
  return 1;
}



/* mkstemp extracted from libc/sysdeps/posix/tempname.c.  Copyright
   (C) 1991-1999, 2000, 2001, 2006 Free Software Foundation, Inc.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.  */

static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX").  The name constructed
   does not exist at the time of the call to mkstemp.  TMPL is
   overwritten with the result.  */
static int
my_mkstemp (char *tmpl)
{
  int len;
  char *XXXXXX;
  static uint64_t value;
  uint64_t random_time_bits;
  unsigned int count;
  int fd = -1;
  int save_errno = errno;

  /* A lower bound on the number of temporary files to attempt to
     generate.  The maximum total number of temporary file names that
     can exist for a given template is 62**6.  It should never be
     necessary to try all these combinations.  Instead if a reasonable
     number of names is tried (we define reasonable as 62**3) fail to
     give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

  /* The number of times to attempt to generate a temporary file.  To
     conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
  unsigned int attempts = TMP_MAX;
#else
  unsigned int attempts = ATTEMPTS_MIN;
#endif

  len = strlen (tmpl);
  if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
    {
      gpg_err_set_errno (EINVAL);
      return -1;
    }

  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6];

  /* Get some more or less random data.  */
  {
    FILETIME ft;

    GetSystemTimeAsFileTime (&ft);
    random_time_bits = (((uint64_t)ft.dwHighDateTime << 32)
                        | (uint64_t)ft.dwLowDateTime);
  }
  value += random_time_bits ^ ((uintptr_t)GetCurrentThreadId ());

  for (count = 0; count < attempts; value += 7777, ++count)
    {
      uint64_t v = value;

      /* Fill in the random bits.  */
      XXXXXX[0] = letters[v % 62];
      v /= 62;
      XXXXXX[1] = letters[v % 62];
      v /= 62;
      XXXXXX[2] = letters[v % 62];
      v /= 62;
      XXXXXX[3] = letters[v % 62];
      v /= 62;
      XXXXXX[4] = letters[v % 62];
      v /= 62;
      XXXXXX[5] = letters[v % 62];

      fd = open (tmpl, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
      if (fd >= 0)
	{
	  gpg_err_set_errno (save_errno);
	  return fd;
	}
      else if (errno != EEXIST)
	return -1;
    }

  /* We got out of the loop because we ran out of combinations to try.  */
  gpg_err_set_errno (EEXIST);
  return -1;
}


int
_gpgme_mkstemp (int *fd, char **name)
{
  char tmp[MAX_PATH + 2];
  char *tmpname;
  int err;

  *fd = -1;
  *name = NULL;

  err = GetTempPathA (MAX_PATH + 1, tmp);
  if (err == 0 || err > MAX_PATH + 1)
    strcpy (tmp,"c:\\windows\\temp");
  else
    {
      int len = strlen(tmp);

      /* GetTempPath may return with \ on the end */
      while(len > 0 && tmp[len - 1] == '\\')
	{
	  tmp[len-1] = '\0';
	  len--;
	}
    }

  tmpname = _gpgme_strconcat (tmp, "\\gpgme-XXXXXX", NULL);
  if (!tmpname)
    return -1;
  *fd = my_mkstemp (tmpname);
  if (*fd < 0)
    {
      free (tmpname);
      return -1;
    }

  *name = tmpname;
  return 0;
}


/* Like access but using windows _waccess */
int
_gpgme_access (const char *path, int mode)
{
  wchar_t *u16 = utf8_to_wchar0 (path);
  int r = _waccess (u16, mode);

  free(u16);
  return r;
}


/* Like CreateProcessA but mapping the arguments to wchar API */
int
_gpgme_create_process_utf8 (const char *application_name_utf8,
                            char *command_line_utf8,
                            LPSECURITY_ATTRIBUTES lpProcessAttributes,
                            LPSECURITY_ATTRIBUTES lpThreadAttributes,
                            BOOL bInheritHandles,
                            DWORD dwCreationFlags,
                            void *lpEnvironment,
                            char *working_directory_utf8,
                            LPSTARTUPINFOA si,
                            LPPROCESS_INFORMATION lpProcessInformation)
{
  BOOL ret;
  wchar_t *application_name = utf8_to_wchar0 (application_name_utf8);
  wchar_t *command_line = utf8_to_wchar0 (command_line_utf8);
  wchar_t *working_directory = utf8_to_wchar0 (working_directory_utf8);

  STARTUPINFOW siw;
  memset (&siw, 0, sizeof siw);
  if (si)
    {
      siw.cb = sizeof (siw);
      siw.dwFlags = si->dwFlags;
      siw.wShowWindow = si->wShowWindow;
      siw.hStdInput = si->hStdInput;
      siw.hStdOutput = si->hStdOutput;
      siw.hStdError = si->hStdError;
      siw.dwX = si->dwX;
      siw.dwY = si->dwY;
      siw.dwXSize = si->dwXSize;
      siw.dwYSize = si->dwYSize;
      siw.dwXCountChars = si->dwXCountChars;
      siw.dwYCountChars = si->dwYCountChars;
      siw.dwFillAttribute = si->dwFillAttribute;
      siw.lpDesktop = utf8_to_wchar0 (si->lpDesktop);
      siw.lpTitle = utf8_to_wchar0 (si->lpTitle);
    }

  ret = CreateProcessW (application_name,
                        command_line,
                        lpProcessAttributes,
                        lpThreadAttributes,
                        bInheritHandles,
                        dwCreationFlags,
                        lpEnvironment,
                        working_directory,
                        si ? &siw : NULL,
                        lpProcessInformation);
  free (siw.lpTitle);
  free (siw.lpDesktop);
  free (application_name);
  free (command_line);
  free (working_directory);
  return ret;
}

/* Entry point called by the DLL loader.  */
#ifdef DLL_EXPORT
int WINAPI
DllMain (HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
  (void)reserved;

  if (reason == DLL_PROCESS_ATTACH)
    my_hmodule = hinst;

  return TRUE;
}
#endif /*DLL_EXPORT*/

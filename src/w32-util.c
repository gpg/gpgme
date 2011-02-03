/* w32-util.c - Utility functions for the W32 API
   Copyright (C) 1999 Free Software Foundation, Inc
   Copyright (C) 2001 Werner Koch (dd9jn)
   Copyright (C) 2001, 2002, 2003, 2004, 2007 g10 Code GmbH

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

#define _WIN32_IE 0x0400 /* Required for SHGetSpecialFolderPathA.  */

/* We need to include the windows stuff here prior to shlobj.h so that
   we get the right winsock version.  This is usually done in util.h
   but that header also redefines some Windows functions which we need
   to avoid unless having included shlobj.h.  */
#include <winsock2.h>
#include <ws2tcpip.h> 
#include <windows.h>
#include <shlobj.h>

#include "util.h"
#include "ath.h"
#include "sema.h"
#include "debug.h"


#ifndef HAVE_W32CE_SYSTEM
#define HAVE_ALLOW_SET_FOREGROUND_WINDOW 1
#endif
#ifndef F_OK
# define F_OK 0
#endif


DEFINE_STATIC_LOCK (get_path_lock);


#ifdef HAVE_ALLOW_SET_FOREGROUND_WINDOW

#define RTLD_LAZY 0

static GPG_ERR_INLINE void *
dlopen (const char * name, int flag)
{
  void * hd = LoadLibrary (name);
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
#endif /* HAVE_ALLOW_SET_FOREGROUND_WINDOW */

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
      TRACE1 (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", 0,
	      "no action for pid %d", (int)pid);
    }
  else if (func)
    {
      int rc = func (pid);
      TRACE2 (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", 0,
	      "called for pid %d; result=%d", (int)pid, rc);

    }
  else
    {
      TRACE0 (DEBUG_ENGINE, "gpgme:AllowSetForegroundWindow", 0,
	      "function not available");
    }
#endif /* HAVE_ALLOW_SET_FOREGROUND_WINDOW */
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

#ifndef HAVE_W32CE_SYSTEM
  /* Windows CE does not have an environment.  */
  if (type == REG_EXPAND_SZ && strchr (result, '%')) 
    {
      char *tmp;
        
      n1 += 1000;
      tmp = malloc (n1 + 1);
      if (!tmp)
        goto leave;
      nbytes = ExpandEnvironmentStrings (result, tmp, n1);
      if (nbytes && nbytes > n1)
        {
          free (tmp);
          n1 = nbytes;
          tmp = malloc (n1 + 1);
          if (!tmp)
            goto leave;
          nbytes = ExpandEnvironmentStrings (result, tmp, n1);
          if (nbytes && nbytes > n1) {
            free (tmp); /* Oops - truncated, better don't expand at all. */
            goto leave;
          }
          tmp[nbytes] = 0;
          free (result);
          result = tmp;
        }
      else if (nbytes)  /* Okay, reduce the length. */
        {
          tmp[nbytes] = 0;
          free (result);
          result = malloc (strlen (tmp)+1);
          if (!result)
            result = tmp;
          else 
            {
              strcpy (result, tmp);
              free (tmp);
            }
        }
      else  /* Error - don't expand. */
        {
          free (tmp);
        }
    }
#endif

 leave:
  RegCloseKey (key_handle);
  return result;
}


#if 0
static char *
find_program_in_registry (const char *name)
{
  char *program = NULL;
    
  program = read_w32_registry_string (NULL, "Software\\GNU\\GnuPG", name);
  if (program)
    {
      int i;

      TRACE2 (DEBUG_CTX, "gpgme:find_program_in_registry", 0,
	      "found %s in registry: `%s'", name, program);
      for (i = 0; program[i]; i++)
	{
	  if (program[i] == '/')
	    program[i] = '\\';
	}
    }
  return program;
}
#endif


static char *
find_program_in_inst_dir (const char *name)
{
  char *result = NULL;
  char *tmp;

  tmp = read_w32_registry_string ("HKEY_LOCAL_MACHINE",
				  "Software\\GNU\\GnuPG",
				  "Install Directory");
  if (!tmp)
    return NULL;

  result = malloc (strlen (tmp) + 1 + strlen (name) + 1);
  if (!result)
    {
      free (tmp);
      return NULL;
    }

  strcpy (stpcpy (stpcpy (result, tmp), "\\"), name);
  free (tmp);
  if (access (result, F_OK))
    {
      free (result);
      return NULL;
    }

  return result;
}


static char *
find_program_at_standard_place (const char *name)
{
  char path[MAX_PATH];
  char *result = NULL;
      
  /* See http://wiki.tcl.tk/17492 for details on compatibility.  */
  if (SHGetSpecialFolderPathA (NULL, path, CSIDL_PROGRAM_FILES, 0))
    {
      result = malloc (strlen (path) + 1 + strlen (name) + 1);
      if (result)
        {
          strcpy (stpcpy (stpcpy (result, path), "\\"), name);
          if (access (result, F_OK))
            {
              free (result);
              result = NULL;
            }
        }
    }
  return result;
}


const char *
_gpgme_get_gpg_path (void)
{
  static char *gpg_program;

  LOCK (get_path_lock);
#if 0
  if (!gpg_program)
    gpg_program = find_program_in_registry ("gpgProgram");
#endif
  if (!gpg_program)
    gpg_program = find_program_in_inst_dir ("gpg.exe");
  if (!gpg_program)
    gpg_program = find_program_at_standard_place ("GNU\\GnuPG\\gpg.exe");
  UNLOCK (get_path_lock);
  return gpg_program;
}


const char *
_gpgme_get_gpgsm_path (void)
{
  static char *gpgsm_program;

  LOCK (get_path_lock);
#if 0
  if (!gpgsm_program)
    gpgsm_program = find_program_in_registry ("gpgsmProgram");
#endif
  if (!gpgsm_program)
    gpgsm_program = find_program_in_inst_dir ("gpgsm.exe");
  if (!gpgsm_program)
    gpgsm_program = find_program_at_standard_place ("GNU\\GnuPG\\gpgsm.exe");
  UNLOCK (get_path_lock);
  return gpgsm_program;
}


const char *
_gpgme_get_gpgconf_path (void)
{
  static char *gpgconf_program;

  LOCK (get_path_lock);
#if 0
  if (!gpgconf_program)
    gpgconf_program = find_program_in_registry ("gpgconfProgram");
#endif
  if (!gpgconf_program)
    gpgconf_program = find_program_in_inst_dir ("gpgconf.exe");
  if (!gpgconf_program)
    gpgconf_program
      = find_program_at_standard_place ("GNU\\GnuPG\\gpgconf.exe");
  UNLOCK (get_path_lock);
  return gpgconf_program;
}


const char *
_gpgme_get_g13_path (void)
{
  static char *g13_program;

  LOCK (get_path_lock);
#if 0
  if (!g13_program)
    g13_program = find_program_in_registry ("g13Program");
#endif
  if (!g13_program)
    g13_program = find_program_in_inst_dir ("g13.exe");
  if (!g13_program)
    g13_program = find_program_at_standard_place ("GNU\\GnuPG\\g13.exe");
  UNLOCK (get_path_lock);
  return g13_program;
}


const char *
_gpgme_get_uiserver_socket_path (void)
{
  static char *socket_path;
  const char *homedir;
  const char name[] = "S.uiserver";

  if (socket_path)
    return socket_path;

  homedir = _gpgme_get_default_homedir ();
  if (! homedir)
    return NULL;

  socket_path = malloc (strlen (homedir) + 1 + strlen (name) + 1);
  if (! socket_path)
    return NULL;

  strcpy (stpcpy (stpcpy (socket_path, homedir), "\\"), name);
  return socket_path;
}


const char *
_gpgme_get_w32spawn_path (void)
{
  static char *w32spawn_program;

  LOCK (get_path_lock);
  if (!w32spawn_program)
    w32spawn_program = find_program_in_inst_dir ("gpgme-w32spawn.exe");
  if (!w32spawn_program)
    w32spawn_program
      = find_program_at_standard_place ("GNU\\GnuPG\\gpgme-w32spawn.exe");
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


#ifdef HAVE_W32CE_SYSTEM
int
_gpgme_mkstemp (int *fd, char **name)
{
  return -1;
}
#else

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
mkstemp (char *tmpl)
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
  value += random_time_bits ^ ath_self ();

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

  tmpname = malloc (strlen (tmp) + 13 + 1);
  if (!tmpname)
    return -1;
  strcpy (stpcpy (tmpname, tmp), "\\gpgme-XXXXXX");
  *fd = mkstemp (tmpname);
  if (fd < 0)
    return -1;

  *name = tmpname;
  return 0;
}
#endif



#ifdef HAVE_W32CE_SYSTEM
/* Return a malloced string with the replacement value for the
   GPGME_DEBUG envvar.  Caller must release.  Returns NULL if not
   set.  */
char *
_gpgme_w32ce_get_debug_envvar (void)
{
  char *tmp;

  tmp = read_w32_registry_string (NULL, "\\Software\\GNU\\gpgme", "debug");
  if (tmp && !*tmp)
    {
      free (tmp);
      tmp = NULL;
    }
  return tmp;
}
#endif /*HAVE_W32CE_SYSTEM*/

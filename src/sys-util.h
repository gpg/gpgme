/* sys-util.h - System utilities not generally used.
 * Copyright (C) 2013 g10 Code GmbH
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
 * License along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef SYS_UTIL_H
#define SYS_UTIL_H

/*-- {posix,w32}-util.c --*/
int _gpgme_set_default_gpg_name (const char *name);
int _gpgme_set_default_gpgconf_name (const char *name);
int _gpgme_set_override_inst_dir (const char *dir);
int _gpgme_set_get_inst_type (const char *value);

char *_gpgme_get_gpg_path (void);
char *_gpgme_get_gpgconf_path (void);

int _gpgme_access (const char *path_utf8, int mode);

#ifdef HAVE_W32_SYSTEM
const char *_gpgme_get_inst_dir (void);
void _gpgme_w32_cancel_synchronous_io (HANDLE thread);
/* See CreateProcessA returns true on success */
int _gpgme_create_process_utf8 (const char *application_name_utf8,
                                char *command_line_utf8,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                void *lpEnvironment,
                                char *working_directory_utf8,
                                LPSTARTUPINFOA lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation);
#endif

#endif /* SYS_UTIL_H */

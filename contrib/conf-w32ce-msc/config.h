/* config.h for building with Visual-C for WindowsCE. 
 * Copyright 2010 g10 Code GmbH
 * 
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 * 
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* This file was originally created by running 
 *   ./autogen.sh --build-w32ce
 * on svn revision 1495 (gpgme 1.3.1-svn1495) and then adjusted to work
 * with Visual-C.
 */

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.3.1-svn1495-msc1"

/* Name of this package */
#define PACKAGE "gpgme"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "bug-gpgme@gnupg.org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "gpgme"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "gpgme " PACKAGE_VERSION

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "gpgme"

/* Define to the home page for this package. */
#define PACKAGE_URL ""



/* Whether Assuan support is enabled */
#define ENABLE_ASSUAN 1

/* Whether G13 support is enabled */
#define ENABLE_G13 1

/* Whether GPGCONF support is enabled */
#define ENABLE_GPGCONF 1

/* Whether GPGSM support is enabled */
#define ENABLE_GPGSM 1

/* Defined if we are building with uiserver support. */
/* #undef ENABLE_UISERVER */

/* Path to the G13 binary. */
#define G13_PATH "c:\\gnupg\\g13.exe"

/* Path to the GPGCONF binary. */
#define GPGCONF_PATH "c:\\gnupg\\gpgconf.exe"

/* version of the libassuan library */
#define GPGME_LIBASSUAN_VERSION "2.0.2-svn381"

/* Path to the GPGSM binary. */
#define GPGSM_PATH "c:\\gnupg\\gpgsm.exe"

/* The default error source for GPGME. */
#define GPG_ERR_SOURCE_DEFAULT GPG_ERR_SOURCE_GPGME

/* Path to the GnuPG binary. */
#define GPG_PATH "c:\\gnupg\\gpg.exe"

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Defined if we run on some of the PCDOS like systems (DOS, Windoze. OS/2)
   with special properties like no file modes */
#define HAVE_DOSISH_SYSTEM 1

/* Define to 1 if the system has the type `error_t'. */
/* #undef HAVE_ERROR_T */

/* Define to 1 if you have the `fopencookie' function. */
/* #undef HAVE_FOPENCOOKIE */

/* Define to 1 if fseeko (and presumably ftello) exists and is declared. */
/* #undef HAVE_FSEEKO */

/* Define to 1 if you have the `funopen' function. */
/* #undef HAVE_FUNOPEN */

/* Define to 1 if you have the `getegid' function. */
/* #undef HAVE_GETEGID */

/* Define to 1 if you have the `getenv_r' function. */
/* #undef HAVE_GETENV_R */

/* Define to 1 if you have the `getgid' function. */
/* #undef HAVE_GETGID */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <locale.h> header file. */
/* #undef HAVE_LOCALE_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if we have Pth. */
/* #undef HAVE_PTH */

/* Define if we have pthread. */
/* #undef HAVE_PTHREAD */

/* Define to 1 if you have the `setenv' function. */
/* #undef HAVE_SETENV */

/* Define to 1 if you have the `setlocale' function. */
/* #undef HAVE_SETLOCALE */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `stpcpy' function. */
/* #undef HAVE_STPCPY */

/* Define to 1 if you have the <strings.h> header file. */
/* #undef HAVE_STRINGS_H */

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
/* #undef HAVE_SYS_SELECT_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
/* #undef HAVE_SYS_STAT_H */

/* Define to 1 if you have the <sys/types.h> header file. */
/* #undef HAVE_SYS_TYPES_H */

/* Define to 1 if you have the <sys/uio.h> header file. */
/* #undef HAVE_SYS_UIO_H */

/* Define if getenv() is thread-safe */
/* #undef HAVE_THREAD_SAFE_GETENV */

/* Define to 1 if you have the `timegm' function. */
/* #undef HAVE_TIMEGM */

/* Define if __thread is supported */
/* #define HAVE_TLS 1 */

/* Define to 1 if you have the `ttyname_r' function. */
/* #undef HAVE_TTYNAME_R */

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Define to 1 if you have the <unistd.h> header file. */
/* #define HAVE_UNISTD_H 1 */

/* Define to 1 if you have the `vasprintf' function. */
/* #undef HAVE_VASPRINTF */

/* Defined if we run on a W32 CE API based system */
#define HAVE_W32CE_SYSTEM 1

/* Defined if we run on a W32 API based system */
#define HAVE_W32_SYSTEM 1

/* Define to the sub-directory in which libtool stores uninstalled libraries.
   */
#define LT_OBJDIR ".libs/"

/* used to implement the va_copy macro */
/* #undef MUST_COPY_VA_BYVAL */

/* Min. needed G13 version. */
#define NEED_G13_VERSION "2.1.0"

/* Min. needed GPGCONF version. */
#define NEED_GPGCONF_VERSION "2.0.4"

/* Min. needed GPGSM version. */
#define NEED_GPGSM_VERSION "1.9.6"

/* Min. needed GnuPG version. */
#define NEED_GPG_VERSION "1.4.0"


/* Separators as used in $PATH.  */
#ifdef HAVE_DOSISH_SYSTEM
#define PATHSEP_C ';'
#else
#define PATHSEP_C ':'
#endif


/* The size of `unsigned int', as computed by sizeof. */
#define SIZEOF_UNSIGNED_INT 4

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Defined if descriptor passing is enabled and supported */
/* #undef USE_DESCRIPTOR_PASSING */

/* Enable extensions on AIX 3, Interix.  */
#ifndef _ALL_SOURCE
# define _ALL_SOURCE 1
#endif
/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif
/* Enable threading extensions on Solaris.  */
#ifndef _POSIX_PTHREAD_SEMANTICS
# define _POSIX_PTHREAD_SEMANTICS 1
#endif
/* Enable extensions on HP NonStop.  */
#ifndef _TANDEM_SOURCE
# define _TANDEM_SOURCE 1
#endif
/* Enable general extensions on Solaris.  */
#ifndef __EXTENSIONS__
# define __EXTENSIONS__ 1
#endif


/* Version of this package */
#define VERSION PACKAGE_VERSION

/* Number of bits in a file offset, on hosts where this is settable. */
/* #undef _FILE_OFFSET_BITS */

/* Define to 1 to make fseeko visible on some hosts (e.g. glibc 2.2). */
/* #undef _LARGEFILE_SOURCE */

/* Define for large files, on AIX-style hosts. */
/* #undef _LARGE_FILES */

/* Define to 1 if on MINIX. */
/* #undef _MINIX */

/* Define to 2 if the system does not provide POSIX.1 features except with
   this defined. */
/* #undef _POSIX_1_SOURCE */

/* Define to 1 if you need to in order for `stat' and other things to work. */
/* #undef _POSIX_SOURCE */

/* To allow the use of GPGME in multithreaded programs we have to use
  special features from the library.
  IMPORTANT: gpgme is not yet fully reentrant and you should use it
  only from one thread.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif

/* Activate POSIX interface on MacOS X */
/* #undef _XOPEN_SOURCE */

/* Define to a type to use for `error_t' if it is not otherwise available. */
#define error_t int

/* Define to `__inline__' or `__inline' if that's what the C compiler
   calls it, or to nothing if 'inline' is not supported under any name.  */
#ifndef __cplusplus
#define inline __inline
#endif

/* Define to `long int' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to the type of an unsigned integer type wide enough to hold a
   pointer, if such a type exists, and if the system does not define it. */
/* #undef uintptr_t */


/* Definition of GCC specific attributes.  */
#if __GNUC__ > 2 
# define GPGME_GCC_A_PURE  __attribute__ ((__pure__))
#else
# define GPGME_GCC_A_PURE
#endif

/* Under WindowsCE we need gpg-error's strerror macro.  */
#define GPG_ERR_ENABLE_ERRNO_MACROS 1

/* snprintf is not part of oldnames.lib thus we redefine it here. */
#define snprintf _snprintf

/* We don't want warnings like this:

   warning C4996: e.g. "The POSIX name for this item is
   deprecated. Instead, use the ISO C++ conformant name: _fileno"

   warning C4018: '<' : signed/unsigned mismatch

   warning C4244: '=' : conversion from 'time_t' to
                        'unsigned long', possible loss of data

 */
#pragma warning(disable:4996 4018 4244)




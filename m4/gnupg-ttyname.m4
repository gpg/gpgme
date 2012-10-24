# gnupg-ttyname.m4
# Copyright (C) 2010-2012 Free Software Foundation, Inc.
# This file is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.
#
# This file is based on gnulib/m4/ttyname_r.m4 serial 8.
#


# gnupg_REPLACE_TTYNAME_R
#
# This macro is an extended version of AC_REPLACE_FUNCS(ttyname_r).
# It takes peculiarities in the implementation of ttyname_r in account.
#
# The macro HAVE_TTYNAME_R will be defined to 1 if the function
# exists; it will be defined to 0 if it does not exists or no
# declaration is available.
#
# The macro HAVE_POSIXDECL_TTYNAME_R is defined if ttyname_r conforms
# to the Posix declaration.
#
# The macro HAVE_BROKEN_TTYNAME_R is defined it ttyname_r does not work
# correctly with the supplied buffer size.  If this is defined the function
# will also be replaced.
#
# The macro REPLACE_TTYNAME_R is defined if ttyname_r is a replacement
# function.  This macro is useful for the definition of the prototype.
#
# If the macro "have_android_system" has a value of "yes", ttyname_r
# will also be replaced by our own function.
#
AC_DEFUN([gnupg_REPLACE_TTYNAME_R],
[
  AC_CHECK_HEADERS([unistd.h])

  AC_CHECK_DECLS_ONCE([ttyname_r])
  if test $ac_cv_have_decl_ttyname_r = no; then
    HAVE_DECL_TTYNAME_R=0
  fi

  AC_CHECK_FUNCS([ttyname_r])
  if test $ac_cv_func_ttyname_r = no; then
    HAVE_TTYNAME_R=0
    AC_LIBOBJ([ttyname_r])
    AC_DEFINE([REPLACE_TTYNAME_R],[1],
              [Define to 1 if ttyname_r is a replacement function.])
  else
    HAVE_TTYNAME_R=1
    dnl On MacOS X 10.4 (and Solaris 10 without __EXTENSIONS__)
    dnl the return type is 'char *', not 'int'.
    AC_CACHE_CHECK([whether ttyname_r is compatible with its POSIX signature],
      [gnupg_cv_func_ttyname_r_posix],
      [AC_COMPILE_IFELSE(
         [AC_LANG_PROGRAM(
            [[#include <stddef.h>
              #include <unistd.h>]],
            [[*ttyname_r (0, NULL, 0);]])
         ],
         [gnupg_cv_func_ttyname_r_posix=no],
         [gnupg_cv_func_ttyname_r_posix=yes])
      ])
    if test $gnupg_cv_func_ttyname_r_posix = no; then
      AC_LIBOBJ([ttyname_r])
      AC_DEFINE([REPLACE_TTYNAME_R],[1])
    elif test "$have_android_system" = yes; then
      # Android has ttyname and ttyname_r but they are only stubs and
      # print an annoying warning message.  Thus we need to replace
      # ttyname_r with our own dummy function.
      AC_LIBOBJ([ttyname_r])
      AC_DEFINE([REPLACE_TTYNAME_R],[1])
    else
      AC_DEFINE([HAVE_POSIXDECL_TTYNAME_R], [1],
        [Define if the ttyname_r function has a POSIX compliant declaration.])
      dnl On Solaris 10, both ttyname_r functions (the one with the non-POSIX
      dnl declaration and the one with the POSIX declaration) refuse to do
      dnl anything when the output buffer is less than 128 bytes large.
      dnl On OSF/1 5.1, ttyname_r ignores the buffer size and assumes the
      dnl buffer is large enough.
      AC_REQUIRE([AC_CANONICAL_HOST])
      AC_CACHE_CHECK([whether ttyname_r works with small buffers],
        [gnupg_cv_func_ttyname_r_works],
        [
          dnl Initial guess, used when cross-compiling or when /dev/tty cannot
          dnl be opened.
changequote(,)dnl
          case "$host_os" in
                      # Guess no on Solaris.
            solaris*) gnupg_cv_func_ttyname_r_works="guessing no" ;;
                      # Guess no on OSF/1.
            osf*)     gnupg_cv_func_ttyname_r_works="guessing no" ;;
                      # Guess yes otherwise.
            *)        gnupg_cv_func_ttyname_r_works="guessing yes" ;;
          esac
changequote([,])dnl
          AC_RUN_IFELSE(
            [AC_LANG_SOURCE([[
#include <fcntl.h>
#include <unistd.h>
int
main (void)
{
  int result = 0;
  int fd;
  char buf[31]; /* use any size < 128 here */

  fd = open ("/dev/tty", O_RDONLY);
  if (fd < 0)
    result |= 16;
  else if (ttyname_r (fd, buf, sizeof (buf)) != 0)
    result |= 17;
  else if (ttyname_r (fd, buf, 1) == 0)
    result |= 18;
  return result;
}]])],
            [gnupg_cv_func_ttyname_r_works=yes],
            [case $? in
               17 | 18) gnupg_cv_func_ttyname_r_works=no ;;
             esac],
            [:])
        ])
      case "$gnupg_cv_func_ttyname_r_works" in
        *yes) ;;
        *) AC_LIBOBJ([ttyname_r])
           AC_DEFINE([REPLACE_TTYNAME_R],[1])
           AC_DEFINE([HAVE_BROKEN_TTYNAME_R], [1],
                     [Define if ttyname_r is does not work with small buffers])
           ;;
      esac
    fi
  fi
])

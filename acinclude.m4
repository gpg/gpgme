dnl Macros to configure GPGME
dnl Copyright (C) 2004 g10 Code GmbH
dnl
dnl This file is part of GPGME.
dnl
dnl GPGME is free software; you can redistribute it and/or modify it
dnl under the terms of the GNU Lesser General Public License as
dnl published by the Free Software Foundation; either version 2.1 of the
dnl License, or (at your option) any later version.
dnl 
dnl GPGME is distributed in the hope that it will be useful, but WITHOUT
dnl ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
dnl or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General
dnl Public License for more details.
dnl 
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

dnl GNUPG_CHECK_VA_COPY()
dnl   Do some check on how to implement va_copy.
dnl   May define MUST_COPY_VA_BY_VAL.
dnl   Actual test code taken from glib-1.1.
AC_DEFUN([GNUPG_CHECK_VA_COPY],
[ AC_MSG_CHECKING(whether va_lists must be copied by value)
  AC_CACHE_VAL(gnupg_cv_must_copy_va_byval,[
    if test "$cross_compiling" = yes; then
      gnupg_cv_must_copy_va_byval=no
    else
      gnupg_cv_must_copy_va_byval=no
      AC_TRY_RUN([
       #include <stdarg.h>
       void f (int i, ...)
       {
          va_list args1, args2;
          va_start (args1, i);
          args2 = args1;
          if (va_arg (args2, int) != 42 || va_arg (args1, int) != 42)
            exit (1);
          va_end (args1);
          va_end (args2);
       }
      
       int main()
       {
          f (0, 42);
            return 0;
       }
      ],gnupg_cv_must_copy_va_byval=yes)
    fi
  ])
  if test "$gnupg_cv_must_copy_va_byval" = yes; then
     AC_DEFINE(MUST_COPY_VA_BYVAL,1,[used to implement the va_copy macro])
  fi
  if test "$cross_compiling" = yes; then
    AC_MSG_RESULT(assuming $gnupg_cv_must_copy_va_byval)
  else
    AC_MSG_RESULT($gnupg_cv_must_copy_va_byval)
  fi
])

dnl LIST_MEMBER()
dnl Check wether an element ist contained in a list.  Set `found' to
dnl `1' if the element is found in the list, to `0' otherwise.
AC_DEFUN([LIST_MEMBER],
[
name=$1
list=$2
found=0

for n in $list; do
  if test "x$name" = "x$n"; then
    found=1
  fi
done
])

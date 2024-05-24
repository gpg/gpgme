# gpgmepp.m4 - autoconf macro to detect gpgmepp.
# Copyright (C) 2002, 2003, 2004, 2011, 2014, 2018, 2020, 2021, 2022, 2024
#               g10 Code GmbH
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# Last-changed: 2024-05-23

dnl
dnl Find gpgrt-config, which uses .pc file
dnl (minimum pkg-config functionality, supporting cross build)
dnl
dnl _AM_PATH_GPGRT_CONFIG
AC_DEFUN([_AM_PATH_GPGRT_CONFIG],[dnl
  AC_PATH_PROG(GPGRT_CONFIG, gpgrt-config, no, [$prefix/bin:$PATH])
  if test "$GPGRT_CONFIG" != "no"; then
    # Determine gpgrt_libdir
    #
    # Get the prefix of gpgrt-config assuming it's something like:
    #   <PREFIX>/bin/gpgrt-config
    gpgrt_prefix=${GPGRT_CONFIG%/*/*}
    possible_libdir1=${gpgrt_prefix}/lib
    # Determine by using system libdir-format with CC, it's like:
    #   Normal style: /usr/lib
    #   GNU cross style: /usr/<triplet>/lib
    #   Debian style: /usr/lib/<multiarch-name>
    #   Fedora/openSUSE style: /usr/lib, /usr/lib32 or /usr/lib64
    # It is assumed that CC is specified to the one of host on cross build.
    if libdir_candidates=$(${CC:-cc} -print-search-dirs | \
          sed -n -e "/^libraries/{s/libraries: =//;s/:/\\
/g;p;}"); then
      # From the output of -print-search-dirs, select valid pkgconfig dirs.
      libdir_candidates=$(for dir in $libdir_candidates; do
        if p=$(cd $dir 2>/dev/null && pwd); then
          test -d "$p/pkgconfig" && echo $p;
        fi
      done)

      for possible_libdir0 in $libdir_candidates; do
        # possible_libdir0:
        #   Fallback candidate, the one of system-installed (by $CC)
        #   (/usr/<triplet>/lib, /usr/lib/<multiarch-name> or /usr/lib32)
        # possible_libdir1:
        #   Another candidate, user-locally-installed
        #   (<gpgrt_prefix>/lib)
        # possible_libdir2
        #   Most preferred
        #   (<gpgrt_prefix>/<triplet>/lib,
        #    <gpgrt_prefix>/lib/<multiarch-name> or <gpgrt_prefix>/lib32)
        if test "${possible_libdir0##*/}" = "lib"; then
          possible_prefix0=${possible_libdir0%/lib}
          possible_prefix0_triplet=${possible_prefix0##*/}
          if test -z "$possible_prefix0_triplet"; then
            continue
          fi
          possible_libdir2=${gpgrt_prefix}/$possible_prefix0_triplet/lib
        else
          possible_prefix0=${possible_libdir0%%/lib*}
          possible_libdir2=${gpgrt_prefix}${possible_libdir0#$possible_prefix0}
        fi
        if test -f ${possible_libdir2}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir2}
        elif test -f ${possible_libdir1}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir1}
        elif test -f ${possible_libdir0}/pkgconfig/gpg-error.pc; then
          gpgrt_libdir=${possible_libdir0}
        fi
        if test -n "$gpgrt_libdir"; then break; fi
      done
    fi
    if test -z "$gpgrt_libdir"; then
      # No valid pkgconfig dir in any of the system directories, fallback
      gpgrt_libdir=${possible_libdir1}
    fi
  else
    unset GPGRT_CONFIG
  fi

  if test -n "$gpgrt_libdir"; then
    GPGRT_CONFIG="$GPGRT_CONFIG --libdir=$gpgrt_libdir"
    if $GPGRT_CONFIG gpg-error >/dev/null 2>&1; then
      GPG_ERROR_CONFIG="$GPGRT_CONFIG gpg-error"
      AC_MSG_NOTICE([Use gpgrt-config with $gpgrt_libdir as gpg-error-config])
      gpg_error_config_version=`$GPG_ERROR_CONFIG --modversion`
    else
      gpg_error_config_version=`$GPG_ERROR_CONFIG --version`
      unset GPGRT_CONFIG
    fi
  elif test "$GPG_ERROR_CONFIG" != "no"; then
    gpg_error_config_version=`$GPG_ERROR_CONFIG --version`
    unset GPGRT_CONFIG
  fi
])

dnl AM_PATH_GPGMEPP([MINIMUM-VERSION,
dnl                 [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl
dnl Test for libgpgmepp and define GPGMEPP_CFLAGS, GPGMEPP_LIBS.
dnl
dnl If a prefix option is not used, the config script is first
dnl searched in $SYSROOT/bin and then along $PATH.  If the used
dnl config script does not match the host specification the script
dnl is added to the gpg_config_script_warn variable.
dnl
AC_DEFUN([AM_PATH_GPGMEPP],[dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl
AC_REQUIRE([_AM_PATH_GPGRT_CONFIG])dnl
  min_gpgmepp_version=ifelse([$1], ,1.23,$1)

  AC_MSG_CHECKING(for GpgME++ - version >= $min_gpgmepp_version)
  ok=no
  if test x"$GPGRT_CONFIG" != x -a "$GPGRT_CONFIG" != "no"; then
    req_major=`echo $min_gpgmepp_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_gpgmepp_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_gpgmepp_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`

    if $GPGRT_CONFIG gpgmepp --exists; then
      gpgmepp_config_version=`$GPGRT_CONFIG gpgmepp --modversion`
      major=`echo $gpgmepp_config_version | \
                 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
      minor=`echo $gpgmepp_config_version | \
                 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
      micro=`echo $gpgmepp_config_version | \
                 sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`

      if test "$major" -gt "$req_major"; then
        ok=yes
      else
        if test "$major" -eq "$req_major"; then
          if test "$minor" -gt "$req_minor"; then
            ok=yes
          else
            if test "$minor" -eq "$req_minor"; then
              if test "$micro" -ge "$req_micro"; then
                ok=yes
              fi
            fi
          fi
        fi
      fi
    fi
  fi

  if test $ok = yes; then
    AC_MSG_RESULT([yes ($gpgmepp_config_version)])
    GPGMEPP_CFLAGS=`$GPGRT_CONFIG gpgmepp --cflags`
    GPGMEPP_LIBS=`$GPGRT_CONFIG gpgmepp --libs`
    ifelse([$2], , :, [$2])
    gpgmepp_config_host=`$GPGRT_CONFIG gpgmepp --variable=host 2>/dev/null || echo none`
    if test x"$gpgmepp_config_host" != xnone ; then
      if test x"$gpgmepp_config_host" != x"$host" ; then
  AC_MSG_WARN([[
***
*** The pkgconfig file `$GPGRT_CONFIG gpgmepp --path` was
*** built for $gpgmepp_config_host and thus may not match the
*** used host $host.
*** You may want to use the configure option --with-libgpgmepp-prefix
*** to specify a matching config script or use \$SYSROOT.
***]])
        gpg_config_script_warn="$gpg_config_script_warn libgpgmepp"
      fi
    fi
  else
    if test -n "$gpgmepp_config_version"; then
        AC_MSG_RESULT([yes ($gpgmepp_config_version)])
    else
        AC_MSG_RESULT(no)
    fi
    GPGMEPP_CFLAGS=""
    GPGMEPP_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGMEPP_CFLAGS)
  AC_SUBST(GPGMEPP_LIBS)
])

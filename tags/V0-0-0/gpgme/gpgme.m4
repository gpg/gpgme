dnl Autoconf macros for libgpgme
dnl $Id$

# Configure paths for GPGME
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch  2000-10-27

dnl AM_PATH_GPGME([MINIMUM-VERSION,
dnl               [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for gpgme, and define GPGME_CFLAGS and GPGME_LIBS
dnl
AC_DEFUN(AM_PATH_GPGME,
[dnl
dnl Get the cflags and libraries from the gpgme-config script
dnl
AC_ARG_WITH(gpgme-prefix,
          [  --with-gpgme-prefix=PFX   Prefix where gpgme is installed (optional)],
          gpgme_config_prefix="$withval", gpgme_config_prefix="")
AC_ARG_ENABLE(gpgmetest,
          [  --disable-gpgmetest    Do not try to compile and run a test gpgme program],
          , enable_gpgmetest=yes)

  if test x$gpgme_config_prefix != x ; then
     gpgme_config_args="$gpgme_config_args --prefix=$gpgme_config_prefix"
     if test x${GPGME_CONFIG+set} != xset ; then
        GPGME_CONFIG=$gpgme_config_prefix/bin/gpgme-config
     fi
  fi

  AC_PATH_PROG(GPGME_CONFIG, gpgme-config, no)
  min_gpgme_version=ifelse([$1], ,1.1.0,$1)
  AC_MSG_CHECKING(for gpgme - version >= $min_gpgme_version)
  no_gpgme=""
  if test "$GPGME_CONFIG" = "no" ; then
    no_gpgme=yes
  else
    GPGME_CFLAGS=`$GPGME_CONFIG $gpgme_config_args --cflags`
    GPGME_LIBS=`$GPGME_CONFIG $gpgme_config_args --libs`
    gpgme_config_version=`$GPGME_CONFIG $gpgme_config_args --version`
    if test "x$enable_gpgmetest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GPGME_CFLAGS"
      LIBS="$LIBS $GPGME_LIBS"
dnl
dnl Now check if the installed gpgme is sufficiently new. Also sanity
dnl checks the results of gpgme-config to some extent
dnl
      rm -f conf.gpgmetest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gpgme.h>

int
main ()
{
    system ("touch conf.gpgmetest");

    if( strcmp( gcry_check_version(NULL), "$gpgme_config_version" ) )
    {
      printf("\n*** 'gpgme-config --version' returned %s, but GPGME (%s)\n",
             "$gpgme_config_version", gcry_check_version(NULL) );
      printf("*** was found! If gpgme-config was correct, then it is best\n");
      printf("*** to remove the old version of GPGME. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If gpgme-config was wrong, set the environment variable GPGME_CONFIG\n");
      printf("*** to point to the correct copy of gpgme-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(gcry_check_version(NULL), GPGME_VERSION ) )
    {
      printf("\n*** GPGME header file (version %s) does not match\n", GPGME_VERSION);
      printf("*** library (version %s)\n", gcry_check_version(NULL) );
    }
    else
    {
      if ( gcry_check_version( "$min_gpgme_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of GPGME (%s) was found.\n",
                gcry_check_version(NULL) );
        printf("*** You need a version of GPGME newer than %s. The latest version of\n",
               "$min_gpgme_version" );
        printf("*** GPGME is always available from ftp://ftp.gnupg.org/pub/gpgme/gnupg.\n");
        printf("*** (It is distributed along with GnuPG).\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the gpgme-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of GPGME, but you can also set the GPGME_CONFIG environment to point to the\n");
        printf("*** correct copy of gpgme-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_gpgme=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_gpgme" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.gpgmetest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$GPGME_CONFIG" = "no" ; then
       echo "*** The gpgme-config script installed by GPGME could not be found"
       echo "*** If GPGME was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the GPGME_CONFIG environment variable to the"
       echo "*** full path to gpgme-config."
     else
       if test -f conf.gpgmetest ; then
        :
       else
          echo "*** Could not run gpgme test program, checking why..."
          CFLAGS="$CFLAGS $GPGME_CFLAGS"
          LIBS="$LIBS $GPGME_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gpgme.h>
],      [ return !!gcry_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding GPGME or finding the wrong"
          echo "*** version of GPGME. If it is not finding GPGME, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means GPGME was incorrectly installed"
          echo "*** or that you have moved GPGME since it was installed. In the latter case, you"
          echo "*** may want to edit the gpgme-config script: $GPGME_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     GPGME_CFLAGS=""
     GPGME_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GPGME_CFLAGS)
  AC_SUBST(GPGME_LIBS)
  rm -f conf.gpgmetest
])



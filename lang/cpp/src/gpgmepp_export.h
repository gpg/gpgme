
#ifndef GPGMEPP_EXPORT_H
#define GPGMEPP_EXPORT_H

#ifdef GPGMEPP_STATIC_DEFINE
#  define GPGMEPP_EXPORT
#  define GPGMEPP_NO_EXPORT
#else
#  ifndef GPGMEPP_EXPORT
#    ifdef KF5Gpgmepp_EXPORTS
        /* We are building this library */
#      define GPGMEPP_EXPORT __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define GPGMEPP_EXPORT __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef GPGMEPP_NO_EXPORT
#    define GPGMEPP_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef GPGMEPP_DEPRECATED
#  define GPGMEPP_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef GPGMEPP_DEPRECATED_EXPORT
#  define GPGMEPP_DEPRECATED_EXPORT GPGMEPP_EXPORT GPGMEPP_DEPRECATED
#endif

#ifndef GPGMEPP_DEPRECATED_NO_EXPORT
#  define GPGMEPP_DEPRECATED_NO_EXPORT GPGMEPP_NO_EXPORT GPGMEPP_DEPRECATED
#endif

#define DEFINE_NO_DEPRECATED 0
#if DEFINE_NO_DEPRECATED
# define GPGMEPP_NO_DEPRECATED
#endif

#endif

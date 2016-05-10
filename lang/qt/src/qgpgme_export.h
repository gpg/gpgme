
#ifndef QGPGME_EXPORT_H
#define QGPGME_EXPORT_H

#ifdef QGPGME_STATIC_DEFINE
#  define QGPGME_EXPORT
#  define QGPGME_NO_EXPORT
#else
#  ifndef QGPGME_EXPORT
#    ifdef BUILDING_QGPGME
        /* We are building this library */
#      ifdef WIN32
#       define QGPGME_EXPORT __declspec(dllexport)
#      else
#       define QGPGME_EXPORT __attribute__((visibility("default")))
#      endif
#    else
        /* We are using this library */
#      ifdef WIN32
#       define QGPGME_EXPORT __declspec(dllimport)
#      else
#       define QGPGME_EXPORT __attribute__((visibility("default")))
#      endif
#    endif
#  endif

#  ifndef QGPGME_NO_EXPORT
#    ifdef WIN32
#     define QGPGME_NO_EXPORT
#    else
#     define QGPGME_NO_EXPORT __attribute__((visibility("hidden")))
#    endif
#  endif
#endif

#ifndef QGPGME_DEPRECATED
#  define QGPGME_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef QGPGME_DEPRECATED_EXPORT
#  define QGPGME_DEPRECATED_EXPORT QGPGME_EXPORT QGPGME_DEPRECATED
#endif

#ifndef QGPGME_DEPRECATED_NO_EXPORT
#  define QGPGME_DEPRECATED_NO_EXPORT QGPGME_NO_EXPORT QGPGME_DEPRECATED
#endif

#define DEFINE_NO_DEPRECATED 0
#if DEFINE_NO_DEPRECATED
# define QGPGME_NO_DEPRECATED
#endif

#endif

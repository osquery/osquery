
#ifndef GOOGLE_GLOG_DLL_DECL_H
#define GOOGLE_GLOG_DLL_DECL_H

#ifdef GLOG_STATIC_DEFINE
#  define GOOGLE_GLOG_DLL_DECL
#  define GLOG_NO_EXPORT
#else
#  ifndef GOOGLE_GLOG_DLL_DECL
#    ifdef GOOGLE_GLOG_IS_A_DLL
        /* We are building this library */
#      define GOOGLE_GLOG_DLL_DECL 
#    else
        /* We are using this library */
#      define GOOGLE_GLOG_DLL_DECL 
#    endif
#  endif

#  ifndef GLOG_NO_EXPORT
#    define GLOG_NO_EXPORT 
#  endif
#endif

#ifndef GLOG_DEPRECATED
#  define GLOG_DEPRECATED __declspec(deprecated)
#endif

#ifndef GLOG_DEPRECATED_EXPORT
#  define GLOG_DEPRECATED_EXPORT GOOGLE_GLOG_DLL_DECL GLOG_DEPRECATED
#endif

#ifndef GLOG_DEPRECATED_NO_EXPORT
#  define GLOG_DEPRECATED_NO_EXPORT GLOG_NO_EXPORT GLOG_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef GLOG_NO_DEPRECATED
#    define GLOG_NO_DEPRECATED
#  endif
#endif

#endif /* GOOGLE_GLOG_DLL_DECL_H */

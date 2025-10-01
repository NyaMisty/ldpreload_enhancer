AC_INIT([enhancer],[1.8])

AC_PROG_CC
AC_LANG_C
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_SYS_LARGEFILE

AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE
AC_C_INLINE

AC_ARG_ENABLE(x11, [  --enable-x11    use libx11 hooks], cf_x11=$enableval)
AC_ARG_WITH(x-includes, [  --with-x-includes       path to X11 includes directory], X11INC="-I$withval" )
AC_ARG_WITH(x-libraries, [  --with-x-libraries     path to X11 libraries directory], X11LIB="-L$withval" )

# New options to enable/disable individual hooks (default: enabled)
AC_ARG_ENABLE([dl],       [  --disable-dl          disable dynamic loader hooks],        [cf_dl=$enableval],       [cf_dl=yes])
AC_ARG_ENABLE([exec],     [  --disable-exec        disable exec()/fork() hooks],         [cf_exec=$enableval],     [cf_exec=yes])
AC_ARG_ENABLE([time],     [  --disable-time        disable time-related hooks],          [cf_time=$enableval],     [cf_time=yes])
AC_ARG_ENABLE([file],     [  --disable-file        disable file I/O hooks],              [cf_file=$enableval],     [cf_file=yes])
AC_ARG_ENABLE([filesys],  [  --disable-filesys     disable filesystem hooks],            [cf_filesys=$enableval],  [cf_filesys=yes])
AC_ARG_ENABLE([socket],   [  --disable-socket      disable socket/network hooks],        [cf_socket=$enableval],   [cf_socket=yes])



if test "$cf_x11" = "yes"
then
AC_CHECK_FILE([/usr/X11/include/X11/X.h], [X11ROOT="/usr/X11"],
							AC_CHECK_FILE([/usr/X11R7/include/X11/X.h], [X11ROOT="/usr/X11R7"],
							AC_CHECK_FILE([/usr/X11R6/include/X11/X.h], [X11ROOT="/usr/X11R6"])
							)
						)
	

if test "X11ROOT" != ""
then
	X11INC="-I$X11ROOT/include"
	X11LIB="-L$X11ROOT/lib"
fi

LDFLAGS="$LDFLAGS $X11LIB"
CFLAGS="$CFLAGS $X11INC"

AC_CHECK_LIB(X11,XOpenDisplay,,)
cf_have_x11=$ac_cv_lib_X11_XOpenDisplay
if test "$cf_have_x11" = "yes"
then
AC_DEFINE([HAVE_X11])
AC_SUBST([X11_HOOKS_OBJ], "x11_hooks.o")
fi
fi

# Resolve per-hook enables into macros and object substitutions
if test "$cf_dl" != "no"; then
  AC_DEFINE([HAVE_DL_HOOKS])
fi

if test "$cf_exec" != "no"; then
  AC_DEFINE([HAVE_EXEC_HOOKS])
fi

if test "$cf_time" != "no"; then
  AC_DEFINE([HAVE_TIME_HOOKS])
fi

if test "$cf_file" != "no"; then
  AC_DEFINE([HAVE_FILE_HOOKS])
fi

if test "$cf_filesys" != "no"; then
  AC_DEFINE([HAVE_FILESYS_HOOKS])
fi

if test "$cf_socket" != "no"; then
  AC_DEFINE([HAVE_SOCKET_HOOKS])
fi


AC_CHECK_LIB(c,unshare,,)
cf_have_unshare=$ac_cv_lib_c_unshare
if test "$cf_have_unshare" = "yes"
then
    AC_DEFINE([HAVE_UNSHARE])
fi


AC_MSG_CHECKING([gettimeofday arguments])
ac_cv_func_which_gettimeofday=""


if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(void *tv, void *tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=voidvoid])
fi


if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(struct timeval *tv, void *tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=void])
fi

if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(struct timeval *restrict tv, void *tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=rtz])
fi

if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(struct timeval *tv, void * restrict tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=rvoid])
fi


if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(struct timeval *restrict tv, void * restrict tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=rtzrvoid])
fi


if test "$ac_cv_func_which_gettimeofday" = ""
then 
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
#define _DEFAULT_SOURCE
#include <sys/time.h>
	    int gettimeofday(struct timeval *tv, struct timezone *tz)
	    { 
		return(0);
	    }
        ])],
    [ac_cv_func_which_gettimeofday=tz])
fi


case "$ac_cv_func_which_gettimeofday" in
rtzrvoid)
AC_MSG_RESULT([struct timeval *restrict tv, void *restrict tz])
AC_DEFINE([GETTIMEOFDAY_RTZRVOID])
break;;

rtz)
AC_MSG_RESULT([struct timeval *restrict tv, void *tz])
AC_DEFINE([GETTIMEOFDAY_RTZ])
break;;


rvoid)
AC_MSG_RESULT([struct timeval *tv, void *restrict tz])
AC_DEFINE([GETTIMEOFDAY_TZRVOID])
break;;

void)
AC_MSG_RESULT([struct timeval *tv, void *tz])
AC_DEFINE([GETTIMEOFDAY_TZVOID])
break;;

voidvoid)
AC_MSG_RESULT([void *tv, void *tz])
AC_DEFINE([GETTIMEOFDAY_VOIDVOID])
break;;


tz)
AC_MSG_RESULT([struct timeval *tv, struct timezone *tz])
AC_DEFINE([GETTIMEOFDAY_TRAD])
break;;

*)
AC_DEFINE([GETTIMEOFDAY_NONE])
AC_MSG_RESULT([unknown result])
break;;
esac


dnl read Makefile.in and write Makefile 
AC_OUTPUT(Makefile)



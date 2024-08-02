dnl> Do not add anything above
AC_INIT([n3n], m4_esyscmd([scripts/version.sh | tr -d '\n']))
dnl> Do not add anything above

# Older versions of the autotools expect to find install-sh here.
AC_CONFIG_AUX_DIR(scripts)

AC_CANONICAL_HOST
AC_PROG_CC
AC_CHECK_TOOL([AR], [ar], [false])
AC_CHECK_TOOL([WINDRES], [windres], [windres])

# The config guess official result for a modern and usual linux computer
# is x86_64-pc-linux-gnu, however the debian package management (and debian
# gcc) refer to this as x86_64-linux-gnu, so fix that..
case "$host" in
    x86_64-pc-linux-gnu)
        host=x86_64-linux-gnu
        ;;
    i686-pc-linux-gnu)
        host=i686-linux-gnu
        ;;
    arm-unknown-linux-gnueabihf)
        host=arm-linux-gnueabihf
        ;;
    aarch64-unknown-linux-gnu)
        host=aarch64-linux-gnu
        ;;
esac

case "$host_os" in
    solaris*)
        # Was in Makefile with the test `uname` -eq "SunOS"
        # and comment "For OpenSolaris (Solaris too?)"
        LIBS="-lsocket -lnsl $LIBS"
        ;;
    mingw*)
        LIBS="-lnetapi32 -lws2_32 -liphlpapi $LIBS"
        EXE=".exe"
        ;;
    *)
        EXE=""
        ;;
esac

AC_ARG_WITH([rundir],
    AS_HELP_STRING([--with-rundir=DIR], [location of the system /run dir]),
    [rundir=$withval],
    [rundir="/run"]
)

AC_ARG_WITH([systemddir],
    AS_HELP_STRING([--with-systemddir=DIR], [Where to install systemd units]),
    [systemddir=$withval],
    [systemddir=""]
)

# TODO: ideally, should use AC_ARG_ENABLE
AC_ARG_WITH([zstd],
    AS_HELP_STRING([--with-zstd], [use zstd library]),
    [], [with_zstd=no])
AS_IF([test "x$with_zstd" != "xno"],
    [AC_CHECK_LIB([zstd], [ZSTD_compress],,
        [AC_MSG_ERROR([zstd library not found])]
    )],
)

# TODO: ideally, should use AC_ARG_ENABLE
AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl], [enable support for OpenSSL])],
    [], [with_openssl=no])
AS_IF([test "x$with_openssl" != xno],
    [AC_CHECK_LIB([crypto], [EVP_CIPHER_CTX_reset],,
        [AC_MSG_ERROR([openssl library not found])]
    )],
)

AC_ARG_ENABLE([miniupnp],
    [AS_HELP_STRING([--enable-miniupnp], [support for miniupnp])],
    [], [enable_miniupnp=no])
AS_IF([test "x$enable_miniupnp" != xno],
    [AC_CHECK_LIB([miniupnpc], [upnpDiscover],,
        [AC_MSG_ERROR([miniupnp library not found])]
    )],
)

AC_ARG_ENABLE([natpmp],
    [AS_HELP_STRING([--enable-natpmp], [support for natpmp])],
    [], [enable_natpmp=no])
AS_IF([test "x$enable_natpmp" != xno],
    [AC_CHECK_LIB([natpmp], [initnatpmp],,
        [AC_MSG_ERROR([natpmp library not found])]
    )],
)

AC_ARG_ENABLE([pcap],
    [AS_HELP_STRING([--enable-pcap], [support for pcap])],
    [], [enable_pcap=no])
AS_IF([test "x$enable_pcap" != xno],
    [AC_CHECK_LIB([pcap], [pcap_set_immediate_mode],,
        [AC_MSG_ERROR([pcap library not found])]
    )],
)

AC_ARG_ENABLE([cap],
    [AS_HELP_STRING([--enable-cap], [support for cap])],
    [], [enable_cap=no])
AS_IF([test "x$enable_cap" != xno],
    [AC_CHECK_LIB([cap], [cap_get_proc],,
        [AC_MSG_ERROR([cap library not found])]
    )],
)

AC_ARG_ENABLE([pthread],
    [AS_HELP_STRING([--enable-pthread], [support for pthread])],
    [], [enable_pthread=no])
AS_IF([test "x$enable_pthread" != xno],
    [AC_CHECK_LIB([pthread], [pthread_mutex_trylock],,
        [AC_MSG_ERROR([pthread library not found])]
    )],
)

# The prefix var has no default at this point, so we cannot eval it without
# this hack
AS_IF([test "x$prefix" = "xNONE" ],
    prefix=/usr/local
)

# The systemd unit dir should be in a sane location (based on the prefix) but
# that is not always a dir underneath the prefix.  Apply another hack
AS_IF([test "x$systemddir" = "x" ],
    AS_IF([test "x$prefix" = "x/usr"],
        systemddir=/lib/systemd/system,
        systemddir=$prefix/lib/systemd/system
    )
)

# All this indirection would be great, if the namespace wasnt poluted
# (and for many of the dirs, if the directories were more modern)
CONFIG_DOCDIR=$(eval echo $(eval echo $docdir))
CONFIG_MANDIR=$(eval echo $(eval echo $mandir))
CONFIG_PREFIX=$prefix
CONFIG_RUNDIR=$rundir
CONFIG_SYSTEMDDIR=$systemddir

configure_command=$0$ac_configure_args_raw

AC_SUBST(CONFIG_DOCDIR)
AC_SUBST(CONFIG_MANDIR)
AC_SUBST(CONFIG_PREFIX)
AC_SUBST(CONFIG_RUNDIR)
AC_SUBST(CONFIG_SYSTEMDDIR)

AC_SUBST(configure_command)
AC_SUBST(host)
AC_SUBST(host_os)
AC_SUBST(EXE)
AC_SUBST(WINDRES)
AC_SUBST(with_openssl)
AC_CONFIG_HEADERS(include/config.h)
AC_CONFIG_FILES(config.mak)

AC_OUTPUT

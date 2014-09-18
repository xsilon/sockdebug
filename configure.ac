AC_PREREQ(2.61)

# package version number (not shared library version)
# odd micro numbers indicate in-progress development
# even micro numbers indicate released versions
m4_define(sockdebug_version_major, 0)
m4_define(sockdebug_version_minor, 1)
m4_define(sockdebug_version_micro, 0)

m4_define([sockdebug_version],
          [sockdebug_version_major.sockdebug_version_minor.sockdebug_version_micro])
m4_define([sockdebug_api_version],
          [sockdebug_version_major.sockdebug_version_minor])

AC_INIT(sockdebug, sockdebug_version)
AM_INIT_AUTOMAKE(sockdebug, sockdebug_version)
AC_CONFIG_HEADERS(config.h)

AC_GNU_SOURCE

AC_SEARCH_LIBS([pthread_create], [pthread], [], [
  AC_MSG_ERROR([unable to find the pthread lib])
])

# Checks for programs.
AC_PROG_LIBTOOL
AM_PROG_CC_C_O
AC_PROG_INSTALL

AC_SUBST(sockdebug_CFLAGS)
AC_SUBST(sockdebug_LIBS)



AC_OUTPUT([
Makefile
src/Makefile
])

echo ""
echo "   sockdebug $VERSION"
echo "   ====================="
echo ""
echo "   To build the project, run \"make\""
echo ""

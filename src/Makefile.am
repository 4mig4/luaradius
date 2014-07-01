AM_CFLAGS = $(LIBLUA_CFLAGS)
AM_LDFLAGS = -shared -no-undefined -module -avoid-version -export-dynamic \
             $(LIBRADIUS_LDFLAGS)

lib_LTLIBRARIES = radius.la

radius_la_SOURCES = \
	radiusclient.c \
	radiusclient.h \
	lradius.c \
	lradius.h

radius_la_LIBADD = $(LIBRADIUS_LIBS) $(LIBLUA_LIBS)

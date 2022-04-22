# $Id: Makefile,v 1.1.1.1 2007/01/11 15:49:52 dhartmei Exp $

PROG=	milter-regex
SRCS=	milter-regex.c eval.c parse.y
MAN=	milter-regex.8

CFLAGS+=	-Wall -Wstrict-prototypes -O0 -g
CFLAGS+=	-I/usr/src/gnu/usr.sbin/sendmail/include -I..
LDADD+=		-lmilter -lpthread -g

install:
	sudo rm -rf /usr/local/libexec/milter-regex
	sudo cp ./milter-regex /usr/local/libexec/
	sudo pkill milter-regex || echo not running
	sleep 5
	sudo /usr/local/libexec/milter-regex

.include <bsd.prog.mk>

.if defined(WANT_LDAP)
LDADD+=		-L/usr/local/lib -lldap_r -llber
.endif


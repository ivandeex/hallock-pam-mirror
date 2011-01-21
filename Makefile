# vi: set ts=4 sw=4
# Hallock
# pam_gmirror module makefile
#
# $Id$
# Copyright (C) 2008-2011, vitki.net
#

CP = /bin/cp -f
RM = /bin/rm -f
SUDO=/usr/bin/sudo
SUCP = $(SUDO) $(CP)
SURM = $(SUDO) $(RM)

help:
	echo "usage: make compile|prepare|install|uninstall|clean|test"

PAM = pam_gmirror
PAM_HELPER = pam_gmirror_helper
PAM_OOPTS = -O2
PAM_CCDEFS = -D_GNU_SOURCE
PAM_ARCHOPTS = -m32 -march=i386 -mtune=generic
PAM_CCOPTS = -Wall -fexceptions -fstack-protector -fasynchronous-unwind-tables -fno-strict-aliasing
PAM_ALLCCOPTS = $(PAM_OOPTS) $(PAM_CCDEFS) $(PAM_ARCHOPTS) $(PAM_CCOPTS)
PAM_LDLIBS = -lpam -ldl -lrt
PAM_LIBDIR = /lib/security
PAM_LIBHELPER = $(PAM_LIBDIR)/$(PAM_HELPER)
PAM_VERBOSE = info
UPDATE_RC = /usr/sbin/update-rc.d
CHKCONFIG = /sbin/chkconfig

$(PAM).so: $(PAM).c
	gcc $(PAM_ALLCCOPTS) -shared -fPIC -DPIC -Wl,-soname -Wl,$@ -o $@ $< $(PAM_LDLIBS)

$(PAM_HELPER): $(PAM_HELPER).c
	gcc $(PAM_ALLCCOPTS) -o $@ $< $(PAM_LDLIBS)

$(PAM)-test: $(PAM).c
	gcc $(PAM_ALLCCOPTS) -DTEST_MAIN -o $@ $< $(PAM_LDLIBS)

prepare:
	$(APT_INSTALL) libpam0g-dev

compile: $(PAM).so $(PAM_HELPER)

clean:
	-$(RM) $(PAM).so $(PAM_HELPER) $(PAM)-test $(PAM)*.o

remake: clean compile

install: compile install-files install-config install-initd

uninstall: uninstall-initd uninstall-files uninstall-config

install-files:
	$(SUCP) gmirror.conf /etc/security/
	$(SUCP) initrd-gmirror /etc/init.d/gmirror
	$(SUCP) gmirror-update /usr/sbin/
	$(SUCP) $(PAM).so $(PAM_LIBDIR)/
	$(SUCP) $(PAM_HELPER) $(PAM_LIBHELPER)
	$(SUDO) chown root:root $(PAM_LIBHELPER)
	$(SUDO) chmod 755 $(PAM_LIBHELPER)
	$(SUDO) chmod u+s $(PAM_LIBHELPER)

uninstall-files:
	-$(SURM) /etc/security/gmirror.conf
	-$(SURM) /usr/sbin/gmirror-update
	-$(SURM) /etc/init.d/gmirror
	-$(SURM) $(PAMLIBDIR)/$(PAM).so
	-$(SURM) $(PAMLIBHELPER)

install-initd:
	-$(SURM) /etc/rc[0123456].d/[SK][0123456789][0123456789]gmirror
	-if test -x $(UPDATE_RC) ; then \
		$(SUDO) $(UPDATE_RC) gmirror defaults ; fi
	-if test -x $(CHKCONFIG) ; then \
		$(SUDO) $(CHKCONFIG) --add gmirror ; \
		$(SUDO) $(CHKCONFIG) --level 2345 gmirror on ; fi

uninstall-initd:
	-if test -x $(UPDATE_RC) ; then $(UPDATE_RC) -f gmirror remove ; fi
	-if test -x $(CHKCONFIG) ; then $(CHKCONFIG) --del gmirror ; fi
	-$(SURM) /etc/rc[0123456].d/[SK][0123456789][0123456789]gmirror

install-config:
	-f=/etc/pam.d/system-auth; \
	test -r $$f || f=/etc/pam.d/common-auth; \
	if [ -r $$f ]; then \
		if grep -q pam_gmirror $$f ; then \
			$(SUDO) perl -pi -e \
				'/^#\s*auth\s+\S+\s+pam_gmirror/ && s/^#+//' \
				$$f; \
		else \
			$(SUDO) sh -c \
				"echo 'auth	optional	pam_gmirror.so	$(PAM_VERBOSE)' >> $$f"; \
		fi \
	fi

uninstall-config:
	-for x in system-auth common-auth common-session; do \
		f=/etc/pam.d/$$x; test -r $$f || continue; \
		$(SUDO) perl -pi -e '/^[^#].*?pam_gmirror/ && s/^/#/' $$f; \
	done

test: $(PAM)-test

test-groups:
	./init-global-groups.sh


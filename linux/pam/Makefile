# Builds pam_phonekey.so. Needs the PAM headers: either the libpam0g-dev
# package, or headers extracted without installing it:
#   apt-get download libpam0g-dev && dpkg-deb -x libpam0g-dev_*.deb /tmp/pam
#   make PAM_INCLUDE=/tmp/pam/usr/include
PAM_INCLUDE ?= /usr/include
LIBPAM ?= /usr/lib/x86_64-linux-gnu/libpam.so.0
CFLAGS ?= -O2 -g
WARN = -Wall -Wextra -Werror -Wformat=2 -Wshadow -Wconversion -Wno-sign-conversion
HARDEN = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC -fvisibility=hidden
EXTRA ?=

all: pam_phonekey.so pam_harness

pam_phonekey.so: pam_phonekey.c
	$(CC) $(CFLAGS) $(WARN) $(HARDEN) $(EXTRA) -I$(PAM_INCLUDE) -shared -Wl,-z,relro,-z,now \
		-Wl,--no-undefined -o $@ $< $(LIBPAM)

# Test program only (never installed): runs a PAM stack from a private config dir.
pam_harness: pam_harness.c
	$(CC) $(CFLAGS) $(WARN) $(EXTRA) -I$(PAM_INCLUDE) -o $@ $< $(LIBPAM)

clean:
	rm -f pam_phonekey.so pam_harness

.PHONY: all clean

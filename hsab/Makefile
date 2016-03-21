P := hsab
CFLAGS := -g3
LDLIBS := -lseccomp -lcrypto

server: server.c

opt: CFLAGS := -O3 -march=core-avx-i
opt: server.c
	$(LINK.c) $^ $(LDLIBS) -o server

release:
	sudo tar czf /tmp/$P.tgz --transform 's,rootfs/,,' rootfs

test:
	sudo chroot --userspec=$$UID:$$GID rootfs /usr/bin/server # TCP port 2222

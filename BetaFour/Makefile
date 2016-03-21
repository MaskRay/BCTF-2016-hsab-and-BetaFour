P := BetaFour
CXXFLAGS := -g3
LDLIBS := -lseccomp -lcrypto

server: server.cc

opt: CXXFLAGS := -O3 -march=core-avx-i
opt: server.cc
	$(LINK.cc) $^ $(LDLIBS) -o server

release:
	tar --owner=root --group=root -czf /tmp/$P.tgz --transform 's,rootfs/,,' rootfs

test:
	sudo chroot --userspec=$$UID:$$GID rootfs /usr/bin/server # TCP port 2223

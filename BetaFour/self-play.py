#!/usr/bin/env python3
from hashlib import sha256
import re, socket, sys

N = 12
R = 10
DELIM = re.compile(r'Column\? $|(lose!|win!|Draw)\n$')
POW = True

def readuntil(f, delim, echo=False):
    data = ''
    while not (data.endswith(delim) if type(delim) == str else delim.search(data)):
        c = f.read(1)
        data += c
        if not c:
            break
    if echo:
        sys.stdout.write(data)
    sys.stdout.flush()
    return data

def proof_of_work(challenge, nzeros):
    zz = '0'*nzeros
    c = 0
    while 1:
        sha = sha256()
        proof = challenge+str(c)
        sha.update(proof.encode('latin-1'))
        if sha.hexdigest()[:nzeros] == zz:
            return proof
        c += 1

def new():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('0', 2223))
    f = s.makefile('rw', encoding='utf-8')
    if POW:
        readuntil(f, "'")
        challenge = readuntil(f, "'")[:-1]
        proof = proof_of_work(challenge, 5)
        f.write(proof+'\n')
        f.flush()
    return s, f

def read_board(f):
    readuntil(f, re.compile(r'012345678901\n$'))
    c = [0]*N
    for i in range(N):
        line = readuntil(f, '\n')
        for j in range(N):
            if line[j] != '.':
                c[j] += 1
    l = readuntil(f, DELIM)
    return not l.endswith('Column? '), c

def arbitrary(f):
    while 1:
        l = readuntil(f, DELIM)
        if not l.endswith('Column? '):
            break
        f.write('0\n')
        f.flush()

s0, f0 = new()
s1, f1 = new()
arbitrary(f1)
for i in range(R-1):
    c0, c1 = [0]*N, [0]*N
    turn = i%2
    end = 0
    while 1:
        if turn:
            echo = True
            stop, cc1 = read_board(f1)
            col1 = [j for j in range(N) if c0[j] < cc1[j]]
            c1 = cc1
            if stop:
                if end:
                    break
                else:
                    end = True
            if col1:
                f0.write(str(col1[0])+'\n')
                f0.flush()
        else:
            echo = False
            stop, cc0 = read_board(f0)
            col0 = [j for j in range(N) if c1[j] < cc0[j]]
            c0 = cc0
            if stop:
                if end:
                    break
                else:
                    end = True
            if col0:
                f1.write(str(col0[0])+'\n')
                f1.flush()
        turn = not turn
arbitrary(f0)
readuntil(f0, '@', True)
readuntil(f1, '@', True)

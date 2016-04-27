#! /usr/bin/env python

import time as Time

from broccoli import *

# Don't mind repr() for floats, since that may be shorter as of Python 2.7.
# Since the time argument might be derived from the the current time, normalize
# the display precision (e.g. prevent a rounding from tripping up a diff
# canonifier's regex).
@event
def test2(a,b,c,d,e,f,g,h,i,j,i6,j6):
    global recv
    recv += 1
    print "==== atomic a %d ====" % recv
    print repr(a), a
    print repr(b), b
    print "%.4f" % c
    print d
    print repr(e), e
    print f
    print repr(g), g
    print repr(h), h
    print repr(i), i
    print repr(j), j
    print repr(i6), i6
    print repr(j6), j6

@event
def new_nf_detect(a,b,c,d,):
    global recv
    recv += 1
    print "==== NF %d ====" % recv
    print repr(a), a
    print repr(b), b
    print repr(c), c
    print repr(d), d



bc = Connection("127.0.0.1:47758")

bc.send("test1",
    int(-10),
    count(2),
    time(current_time()),
    interval(120),
    bool(False),
    double(1.5),
    string("Servus"),
    port("5555/tcp"),
    addr("6.7.6.5"),
    subnet("192.168.0.0/16"),
    addr("2001:db8:85a3::8a2e:370:7334"),
    subnet("2001:db8:85a3::/48")
    )

recv = 0
while True:
    bc.processInput();

    Time.sleep(1)


#!/usr/bin/env python

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

from multiprocessing import Process, Lock, Value
import subprocess
import argparse

import socket
import fcntl
import struct
import timeit


P = 3298723423324


# See: http://stackoverflow.com/questions/24196932/how-can-i-get-the-ip-address-of-eth0-in-python
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def largest_prime_factor(n):
    i = 2
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
    return n


def init(e, po, n, j, l, count):
    subprocess.call("echo 'hi' > /dev/null", shell=True)
    netcat(e, po, "hello")

    l.acquire()
    try:
        count.value = count.value + 1
    finally:
        l.release()

    if j >= n:
        largest_prime_factor(P)
        return

    procs = []
    for i in xrange(n):
        p = Process(target=init, args=(e, po, n, j + i + 1, l, count))
        p.start()
        procs.append(p)

    for p in procs:
        p.join()


# See: http://stackoverflow.com/questions/1908878/netcat-implementation-in-python
def netcat(hostname, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((hostname, int(port)))
    s.sendall(content)
    s.shutdown(socket.SHUT_WR)
    s.close()


def expect(n):
    return (2**n) * n


def main(args):
    e = get_ip_address(args.i)
    k = expect(args.n)
    print ("Expecting %d (default shell) processes" % k)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((e, args.p))

    c = Value('i', 0)
    l = Lock()
    for i in xrange(args.n):
        init(e, args.p, args.n, i, l, c)
    print("Executed %d (default shell) processes" % c.value)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=("Place the system under stress."
            " This will launch lots of shells and each will connect to a UDP socket."))
    parser.add_argument("-n", type=int, default=4, help="Expotential intensity")
    parser.add_argument("-i", required=True, help="Network interface for socket actions")
    parser.add_argument("-p", type=int, default=9090, help="Local network UDP port")
    args = parser.parse_args()

    start = timeit.default_timer()
    main(args)
    print("Elapsed: " + str(timeit.default_timer() - start))


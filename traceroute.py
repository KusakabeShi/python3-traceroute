#!/usr/bin/python3

import socket
import struct
import sys
from scapy.all import *

# We want unbuffered stdout so we can provide live feedback for
# each TTL. You could also use the "-u" flag to Python.
class flushfile(type(sys.stdout)):
    def __init__(self, f):
        self.f = f
    def write(self, x):
        try:
            self.f.write(x)
            self.f.flush()
        except Exception as e:
            pass

sys.stdout = flushfile(sys.stdout)

def main(dest_name,dport,sport,af=4):
    if af == 4:
        AF = socket.AF_INET
        IPP = IP
    elif af == 6:
        AF = socket.AF_INET6
        IPP = IPv6
    dest_addr = socket.getaddrinfo(dest_name, None, AF)[0][4][0]
    max_hops = 30
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
        recv_socket = socket.socket(AF, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(AF, socket.SOCK_DGRAM, udp)
        send_socket.bind(("",sport))
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

        # Build the GNU timeval struct (seconds, microseconds)
        timeout = struct.pack("ll", 1, 0)

        # Set the receive timeout so we behave more like regular traceroute
        recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        recv_socket.bind(("", dport))
        sys.stdout.write(" %d  " % ttl)
        send_socket.sendto(b"", (dest_addr, dport))
        curr_addr = None
        curr_name = None
        finished = False
        tries = 3
        while not finished and tries > 0:
            try:
                c, curr_addr = recv_socket.recvfrom(512)
                p = IPP(c)
                pl = p.getlayer("IPerror")
                if pl == None:
                    curr_addr = None
                    continue
                if pl.dst != dest_addr:
                    curr_addr = None
                    continue
                finished = True
                curr_addr = curr_addr[0]
                try:
                    curr_name = socket.gethostbyaddr(curr_addr)[0]
                except socket.error:
                    curr_name = curr_addr
            except socket.error as e:
                tries = tries - 1
                sys.stdout.write("* ")

        send_socket.close()
        recv_socket.close()

        if not finished:
            pass

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = ""
        sys.stdout.write("%s\n" % (curr_host))

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break
    os._exit(0)

if __name__ == "__main__":
    main(sys.argv[1],int(sys.argv[2]),int(sys.argv[3]))

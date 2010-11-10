#!/usr/bin/env python

import sys
import socket

CTRL_SOCKET = "/tmp/vncproxy.sock"

def request_forwarding(sport, daddr, dport, password):
    sport = str(int(sport))
    dport = str(int(dport))
    assert(len(password) > 0)

    request = ":".join([sport, daddr, dport, password])

    ctrl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    ctrl.connect(CTRL_SOCKET)
    ctrl.send(request)
    response = ctrl.recv(1024)
    if response == "OK":
        return True
    else:
        return False

if __name__ == '__main__':
    request_forwarding(*sys.argv[1:])

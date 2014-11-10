# Copyright (c) 2014 Greek Research and Technology Network S.A.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.


from threading import Lock, Event


class Timeout(Exception):
    pass


class CircularBuffer(object):
    """A circular buffer, accesible via read() and write()."""
    def __init__(self, size=16384):
        self.size = size

        self.rcnt = 0  # Total number of bytes read from the buffer
        self.wcnt = 0  # Total number of bytes written to the buffer
        self.data = self.size * ['\0']

        self.mutex = Lock()
        self.nonempty = Event()
        self.nonempty.clear()
        self.notfull = Event()
        self.notfull.set()

        self.blocking = True

    def setblocking(self, val):
        self.blocking = bool(val)

    def read(self, n):
        """Read up to n bytes from the circular buffer.

        Read up to n bytes from the circular buffer,
        and return them as a string.

        Block if no data are available.

        """
        while True:
            with self.mutex:
                if self.nonempty.is_set():
                    # Determine number of bytes to read
                    cur = self.wcnt - self.rcnt
                    assert cur > 0
                    if n > cur:
                        n = cur
                    start = self.rcnt % self.size
                    end = (self.rcnt + n) % self.size

                    # Reset the counters
                    self.rcnt = start
                    self.wcnt = self.rcnt + cur

                    if start < end:
                        data = self.data[start:end]
                    else:
                        data = self.data[start:] + self.data[:end]

                    self.rcnt += n
                    if cur - n == 0:
                        self.nonempty.clear()
                    if n > 0:
                        self.notfull.set()

                    return ''.join(data)

            # We block without holding the mutex
            if not self.blocking:
                raise Timeout("read operation would block")
            self.nonempty.wait()

    def write(self, data):
        """Write up to n bytes into the circular buffer.

        Write up to n bytes into the circular buffer,
        block if no data are available.

        """
        n = len(data)
        while True:
            with self.mutex:
                if self.notfull.is_set():
                    # Determine number of bytes to write
                    cur = self.wcnt - self.rcnt
                    left = self.size - cur
                    assert cur >= 0
                    assert left > 0
                    if n > left:
                        n = left

                    start = self.wcnt % self.size
                    for i in range(n):
                        self.data[(i+start) % self.size] = data[i]

                    self.wcnt += n
                    assert cur + n <= self.size
                    if cur + n == self.size:
                        self.notfull.clear()
                    self.nonempty.set()
                    return n

            # We block without holding the mutex
            if not self.blocking:
                raise Timeout("write operation would block")
            self.notfull.wait()

    def readall(self, n):
        pass

    def writeall(self, data):
        data_len = len(data)
        n = self.write(data)

        while n < data_len:
            n += self.write(data[n:])

        assert(n == data_len)

        return n

    def close(self):
        pass

    # Handy aliases
    recv = read
    send = write
    recvall = readall
    sendall = writeall

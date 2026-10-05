#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import socket
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def checksum(data):
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return ~value & 65535


def ipv4(data, *, ihl=5, length=None, flags=0, options=b'', protocol=17):
    header = struct.pack('!BBHHHBBH4s4s', 0x40 | ihl, 0,
                         20 + len(options) + len(data) if length is None else length,
                         123, flags, 64, protocol, 0,
                         socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1'))
    header += options
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + data


def ethernet(data, tags=0, protocol=0x0800):
    return (bytes(12) + struct.pack('!H', 0x8100 if tags else protocol)
            + b''.join(struct.pack('!HH', 1, 0x8100 if i + 1 < tags else protocol)
                       for i in range(tags)) + data)


def capture(packet, *, caplen=None, wirelen=None):
    caplen = len(packet) if caplen is None else caplen
    wirelen = caplen if wirelen is None else wirelen
    return (struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, max(caplen, 1), 1)
            + struct.pack('<IIII', 0, 0, caplen, wirelen) + packet)


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as directory, socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(('127.0.0.1', 0))
        port = receiver.getsockname()[1]

        def udp(payload=b'packet-validation', length=None):
            return struct.pack('!HHHH', 12345, port,
                               len(payload) + 8 if length is None else length, 0) + payload

        def check(name, contents, payload=None, error=None, allow_size_limit=False):
            path = Path(directory) / (name + '.pcap')
            path.write_bytes(contents)
            result = subprocess.run([binary, '-c', '0', str(path)],
                                    capture_output=True, text=True, timeout=5)
            size_limited = (allow_size_limit and sys.platform == 'darwin'
                            and result.returncode == 1
                            and result.stderr.strip() == 'sendto: Message too long')
            if size_limited:
                # macOS commonly limits outgoing UDP datagrams below 65,507
                # bytes. The parser must still accept this valid packet and
                # reach sendto, which reports the OS limit.
                payload = None
            elif error:
                assert result.returncode == 1, (name, result)
                assert error in result.stderr, (name, result.stderr)
                assert 'AddressSanitizer' not in result.stderr, (name, result.stderr)
                assert 'runtime error:' not in result.stderr, (name, result.stderr)
            else:
                assert result.returncode == 0, (name, result.stderr)
            receiver.settimeout(0.02 if payload is None else 2)
            try:
                received = receiver.recv(65535)
            except TimeoutError:
                received = None
            assert received == payload, (name, None if received is None else len(received))
            print(name + (': PASS (OS datagram limit)' if size_limited else ': PASS'))

        for name, payload, tags, options, flags in [
            ('ordinary', b'packet-validation', 0, b'', 0),
            ('vlan', b'vlan', 1, b'', 0),
            ('double-vlan', b'double-vlan', 2, b'', 0),
            ('ip-options', b'options', 0, b'\x01' * 4, 0),
            ('empty-udp', b'', 0, b'', 0),
            ('large-udp', b'A' * 3000, 0, b'', 0),
            ('maximum-udp', b'A' * 65507, 0, b'', 0),
            ('dont-fragment', b'DF', 0, b'', 0x4000),
        ]:
            packet = ethernet(ipv4(udp(payload), ihl=5 + len(options) // 4,
                                   options=options, flags=flags), tags)
            check(name, capture(packet), payload=payload,
                  allow_size_limit=name == 'maximum-udp')
        check('ethernet-padding', capture(ethernet(ipv4(udp(b'padding'))) + bytes(30)),
              payload=b'padding')

        for name, flags in [('first-fragment', 0x2000),
                            ('intermediate-fragment', 0x2000 | 185),
                            ('final-fragment', 185), ('offset-only', 1)]:
            check(name, capture(ethernet(ipv4(udp(), flags=flags))),
                  error='IPv4 fragments are not supported')
        # Reproduce issue #36's first fragment and full-datagram UDP length.
        check('mtu-fragment', capture(ethernet(ipv4(udp(b'A' * 3000)[:1480], flags=0x2000))),
              error='IPv4 fragments are not supported')

        invalid = [
            ('empty-frame', b''),
            ('short-ethernet', bytes(13)),
            ('short-vlan', bytes(12) + b'\x81\x00' + bytes(3)),
            ('short-inner-vlan', bytes(12) + b'\x81\x00\x00\x01\x81\x00'),
            ('short-ip', ethernet(bytes(19))),
            ('small-ihl', ethernet(ipv4(udp(), ihl=4))),
            ('large-ihl', ethernet(ipv4(udp(), ihl=15))),
            ('short-options', ethernet(ipv4(b'', ihl=6))),
            ('small-ip-length', ethernet(ipv4(udp(), length=19))),
            ('oversized-ip-length', ethernet(ipv4(udp(), length=65535))),
            ('short-udp-header', ethernet(ipv4(bytes(7)))),
            ('zero-udp-length', ethernet(ipv4(udp(length=0)))),
            ('small-udp-length', ethernet(ipv4(udp(length=7)))),
            ('oversized-udp-length', ethernet(ipv4(udp(length=65535)))),
            # Available captured bytes must not override a shorter IP length.
            ('udp-past-ip-length', ethernet(ipv4(udp(), length=28))),
        ]
        for name, packet in invalid:
            check(name, capture(packet), error='Invalid packet:')
        check('snaplen-truncation', capture(ethernet(ipv4(udp())), wirelen=1000),
              error='captured and original lengths differ')
        check('invalid-record-length', capture(ethernet(ipv4(udp())), wirelen=1),
              error='captured and original lengths differ')
        check('truncated-record', capture(bytes(5), caplen=14), error='pcap_read:')
        check('non-ip', capture(ethernet(bytes(28), protocol=0x0806)))
        check('non-udp', capture(ethernet(ipv4(bytes(20), protocol=6))))


if __name__ == '__main__':
    main()

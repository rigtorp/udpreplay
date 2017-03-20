# udpreplay

*udpreplay* is a lightweight alternative
to [tcpreplay](http://tcpreplay.appneta.com/) for replaying UDP
unicast and multicast streams from a pcap file.

## Usage

```
udpreplay [-i iface] [-l] [-s speed] [-t ttl] pcap

  -i iface    interface to send packets through
  -l          enable loopback
  -s speed    replay speed relative to pcap timestamps
  -t ttl      packet ttl
```

## Example

```
$ udpreplay -i eth0 example.pcap
```

## Building & Installing

*udpreplay* requires [CMake](https://cmake.org/) 3.2 or higher to
build and install.

Building:

```
$ cd udpreplay
$ mkdir build
$ cd build
$ cmake ..
$ make
```

Installing:

```
$ make install
```

## About

This project was created by [Erik Rigtorp](http://rigtorp.se)
<[erik@rigtorp.se](mailto:erik@rigtorp.se)>.

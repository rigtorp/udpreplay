# udpreplay

[![Build Status](https://travis-ci.org/rigtorp/udpreplay.svg?branch=master)](https://travis-ci.org/rigtorp/udpreplay)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/rigtorp/udpreplay/master/LICENSE)

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
  -b          enable broadcast (SO_BROADCAST)
```

## Example

```
$ udpreplay -i eth0 example.pcap
```

## Building & Installing

*udpreplay* requires [CMake](https://cmake.org/) 3.2 or higher 
and libpcap-dev to build and install.

```
sudo apt install cmake libpcap-dev
```

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

# udpreplay

[![Build Status](https://travis-ci.org/rigtorp/udpreplay.svg?branch=master)](https://travis-ci.org/rigtorp/udpreplay)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/rigtorp/udpreplay/master/LICENSE)

*udpreplay* is a lightweight alternative
to [tcpreplay](http://tcpreplay.appneta.com/) for replaying UDP
unicast and multicast streams from a pcap file.

## Usage

```
usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r repeat] [-t ttl] pcap

  -i iface    interface to send packets through
  -l          enable loopback
  -c millisec constant milliseconds between packets
  -r repeat   number of times to loop data
  -s speed    replay speed relative to pcap timestamps
  -t ttl      packet ttl
  -b          enable broadcast (SO_BROADCAST)
```

## Example

```
$ udpreplay -i eth0 example.pcap
```

## Building & Installing

*udpreplay* requires [CMake](https://cmake.org/) 3.2 or higher,  
g++ and libpcap-dev to build and install.

Building on Debian/Ubuntu:

```
sudo apt install cmake libpcap-dev g++
cd udpreplay
mkdir build && cd build
cmake ..
make
```

Building on RHEL/CentOS:

```
sudo yum install cmake3 libpcap-devel gcc-c++
cd udpreplay
mkdir build && cd build
cmake3 ..
make
```

Installing:

```
$ sudo make install
```

## About

This project was created by [Erik Rigtorp](http://rigtorp.se)
<[erik@rigtorp.se](mailto:erik@rigtorp.se)>.

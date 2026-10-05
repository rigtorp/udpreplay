# udpreplay

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

Requires Linux or macOS, CMake 3.20+, a C++11 compiler, and libpcap headers
and libraries. On macOS, install the Xcode Command Line Tools and run
`brew install cmake libpcap`.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
cmake --install build --config Release --prefix "$HOME/.local"
```

The executable is installed in `$HOME/.local/bin`. For libpcap in a custom
location, add `-DCMAKE_PREFIX_PATH=/path/to/libpcap` when configuring.

Linux timing tests are enabled by default when Expect is installed. Run them
with `ctest --test-dir build --output-on-failure`, or disable them with
`-DBUILD_TESTING=OFF` when configuring.

## About

This project was created by [Erik Rigtorp](http://rigtorp.se)
<[erik@rigtorp.se](mailto:erik@rigtorp.se)>.

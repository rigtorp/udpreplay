// © 2020 Erik Rigtorp <erik@rigtorp.se>
// SPDX-License-Identifier: MIT

#include <cstring>
#include <iostream>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>

#define NANOSECONDS_PER_SECOND 1000000000L

int main(int argc, char *argv[]) {

  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  int interval = -1;
  int repeat = 1;
  int ttl = -1;
  int broadcast = 0;

  int opt;
  while ((opt = getopt(argc, argv, "i:bls:c:r:t:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = std::stod(optarg);
      if (speed < 0) {
        std::cerr << "speed must be positive" << std::endl;
      }
      break;
    case 'c':
      interval = std::stoi(optarg);
      if (interval < 0) {
        std::cerr << "interval must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'r':
      repeat = std::stoi(optarg);
      if (repeat != -1 && repeat <= 0) {
        std::cerr << "repeat must be positive integer or -1" << std::endl;
        return 1;
      }
      break;
    case 't':
      ttl = std::stoi(optarg);
      if (ttl < 0) {
        std::cerr << "ttl must be non-negative integer" << std::endl;
        return 1;
      }
      break;
    case 'b':
      broadcast = 1;
      break;
    default:
      goto usage;
    }
  }
  if (optind >= argc) {
  usage:
    std::cerr
        << "udpreplay 1.0.0 © 2020 Erik Rigtorp <erik@rigtorp.se> "
           "https://github.com/rigtorp/udpreplay\n"
           "usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r "
           "repeat] [-t ttl] "
           "pcap\n"
           "\n"
           "  -i iface    interface to send packets through\n"
           "  -l          enable loopback\n"
           "  -c millisec constant milliseconds between packets\n"
           "  -r repeat   number of times to loop data (-1 for infinite loop)\n"
           "  -s speed    replay speed relative to pcap timestamps\n"
           "  -t ttl      packet ttl\n"
           "  -b          enable broadcast (SO_BROADCAST)"
        << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (broadcast != 0) {
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast,
                   sizeof(broadcast)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  timespec deadline = {};
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
    return 1;
  }

  for (int i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    timespec start = {-1, -1};
    timespec pcap_start = {-1, -1};

    pcap_pkthdr header;
    const u_char *p;
    while ((p = pcap_next(handle, &header))) {
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          return 1;
        }
        pcap_start.tv_sec = header.ts.tv_sec;
        pcap_start.tv_nsec =
            header.ts.tv_usec; // Note PCAP_TSTAMP_PRECISION_NANO
      }
      if (header.len != header.caplen) {
        continue;
      }
      auto eth = reinterpret_cast<const ether_header *>(p);

      // jump over and ignore vlan tags
      while (ntohs(eth->ether_type) == ETHERTYPE_VLAN) {
        p += 4;
        eth = reinterpret_cast<const ether_header *>(p);
      }
      if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        continue;
      }
      auto ip = reinterpret_cast<const struct ip *>(p + sizeof(ether_header));
      if (ip->ip_v != 4) {
        continue;
      }
      if (ip->ip_p != IPPROTO_UDP) {
        continue;
      }
      auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                  ip->ip_hl * 4);
      if (interval != -1) {
        // Use constant packet rate
        deadline.tv_sec += interval / 1000L;
        deadline.tv_nsec += (interval * 1000000L) % NANOSECONDS_PER_SECOND;
      } else {
        // Next packet deadline = start + (packet ts - first packet ts) * speed
        int64_t delta =
            (header.ts.tv_sec - pcap_start.tv_sec) * NANOSECONDS_PER_SECOND +
            (header.ts.tv_usec -
             pcap_start.tv_nsec); // Note PCAP_TSTAMP_PRECISION_NANO
        if (speed != 1.0) {
          delta *= speed;
        }
        deadline = start;
        deadline.tv_sec += delta / NANOSECONDS_PER_SECOND;
        deadline.tv_nsec += delta % NANOSECONDS_PER_SECOND;
      }

      // Normalize timespec
      if (deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
        deadline.tv_sec++;
        deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
      }

      timespec now = {};
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
        return 1;
      }

      if (deadline.tv_sec > now.tv_sec ||
          (deadline.tv_sec == now.tv_sec && deadline.tv_nsec > now.tv_nsec)) {
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
                            nullptr) == -1) {
          std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
          return 1;
        }
      }

#ifdef __GLIBC__
      ssize_t len = ntohs(udp->len) - 8;
#else
      ssize_t len = ntohs(udp->uh_ulen) - 8;
#endif
      const u_char *d =
          &p[sizeof(ether_header) + ip->ip_hl * 4 + sizeof(udphdr)];

      sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
#ifdef __GLIBC__
      addr.sin_port = udp->dest;
#else
      addr.sin_port = udp->uh_dport;
#endif
      addr.sin_addr = {ip->ip_dst};
      auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                      sizeof(addr));
      if (n != len) {
        std::cerr << "sendto: " << strerror(errno) << std::endl;
        return 1;
      }
    }

    pcap_close(handle);
  }

  return 0;
}

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

  timespec start = {-1, -1};

  for (int i = 0; repeat == -1 || i < repeat; i++) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);

    if (handle == nullptr) {
      std::cerr << "pcap_open: " << errbuf << std::endl;
      return 1;
    }

    auto packet_error = [&](const char *message) {
      std::cerr << message << std::endl;
      pcap_close(handle);
      return 1;
    };

    timespec pcap_start = {-1, -1};
    int64_t last_delta = 0;

    pcap_pkthdr *packet_header;
    const u_char *p;
    int packet_status;
    while ((packet_status = pcap_next_ex(handle, &packet_header, &p)) == 1) {
      const auto &header = *packet_header;
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          std::cerr << "clock_gettime: " << strerror(errno) << std::endl;
          return 1;
        }
      }
      if (pcap_start.tv_nsec == -1) {
        pcap_start.tv_sec = header.ts.tv_sec;
        pcap_start.tv_nsec =
            header.ts.tv_usec; // Note PCAP_TSTAMP_PRECISION_NANO
      }
      if (header.len != header.caplen) {
        return packet_error("Invalid packet: captured and original lengths differ");
      }
      if (header.caplen < sizeof(ether_header)) {
        return packet_error("Invalid packet: truncated Ethernet header");
      }
      ether_header eth;
      memcpy(&eth, p, sizeof(eth));
      size_t offset = sizeof(eth);
      auto protocol = ntohs(eth.ether_type);

      // Jump over VLAN tags, checking each tag before reading its protocol.
      while (protocol == ETHERTYPE_VLAN) {
        if (header.caplen - offset < 4) {
          return packet_error("Invalid packet: truncated VLAN header");
        }
        uint16_t encapsulated_protocol;
        memcpy(&encapsulated_protocol, p + offset + 2,
               sizeof(encapsulated_protocol));
        protocol = ntohs(encapsulated_protocol);
        offset += 4;
      }
      if (protocol != ETHERTYPE_IP) {
        continue;
      }
      if (header.caplen - offset < sizeof(struct ip)) {
        return packet_error("Invalid packet: truncated IPv4 header");
      }
      // Ethernet payloads need not be aligned for native IP/UDP structs.
      struct ip ip;
      memcpy(&ip, p + offset, sizeof(ip));
      if (ip.ip_v != 4) {
        continue;
      }
      const size_t ip_header_length = ip.ip_hl * 4;
      const size_t ip_length = ntohs(ip.ip_len);
      if (ip_header_length < sizeof(ip) ||
          ip_header_length > header.caplen - offset ||
          ip_length < ip_header_length || ip_length > header.caplen - offset) {
        return packet_error("Invalid packet: invalid IPv4 length");
      }
      if (ip.ip_p != IPPROTO_UDP) {
        continue;
      }
      if (ntohs(ip.ip_off) & (IP_MF | IP_OFFMASK)) {
        return packet_error("IPv4 fragments are not supported; reassemble the "
                            "capture before replay");
      }
      if (ip_length - ip_header_length < sizeof(udphdr)) {
        return packet_error("Invalid packet: truncated UDP header");
      }
      udphdr udp;
      memcpy(&udp, p + offset + ip_header_length, sizeof(udp));
#ifdef __GLIBC__
      const size_t udp_length = ntohs(udp.len);
#else
      const size_t udp_length = ntohs(udp.uh_ulen);
#endif
      if (udp_length < sizeof(udp) || udp_length > ip_length - ip_header_length) {
        return packet_error("Invalid packet: invalid UDP length");
      }
      const ssize_t len = udp_length - sizeof(udp);
      const u_char *d = p + offset + ip_header_length + sizeof(udp);
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
        last_delta = delta;
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
#if _POSIX_C_SOURCE >= 200112L && !defined(__APPLE__)
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline,
                            nullptr) == -1) {
          std::cerr << "clock_nanosleep: " << strerror(errno) << std::endl;
          return 1;
        }
#else
        timespec duration;
        duration.tv_sec = deadline.tv_sec - now.tv_sec;
        duration.tv_nsec = deadline.tv_nsec - now.tv_nsec;
        if (duration.tv_nsec < 0) {
          --duration.tv_sec;
          duration.tv_nsec += NANOSECONDS_PER_SECOND;
        }
        if (nanosleep(&duration, nullptr) == -1) {
          std::cerr << "nanosleep: " << strerror(errno) << std::endl;
          return 1;
        }
#endif
      }

      sockaddr_in addr;
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
#ifdef __GLIBC__
      addr.sin_port = udp.dest;
#else
      addr.sin_port = udp.uh_dport;
#endif
      addr.sin_addr = ip.ip_dst;
      auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                      sizeof(addr));
      if (n != len) {
        std::cerr << "sendto: " << strerror(errno) << std::endl;
        return 1;
      }
    }

    if (packet_status == -1) {
      std::cerr << "pcap_read: " << pcap_geterr(handle) << std::endl;
      pcap_close(handle);
      return 1;
    }
    pcap_close(handle);

    if (interval == -1 && start.tv_nsec != -1) {
      start.tv_sec += last_delta / NANOSECONDS_PER_SECOND;
      start.tv_nsec += last_delta % NANOSECONDS_PER_SECOND;
      if (start.tv_nsec >= NANOSECONDS_PER_SECOND) {
        start.tv_sec++;
        start.tv_nsec -= NANOSECONDS_PER_SECOND;
      }
    }
  }

  return 0;
}

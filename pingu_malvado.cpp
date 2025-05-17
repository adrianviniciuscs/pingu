#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>

uint16_t checksum(void *data, int len) {
  uint16_t *ptr = static_cast<uint16_t *>(data);
  uint32_t sum = 0;
  for (; len > 1; len -= 2) sum += *ptr++;
  if (len == 1) sum += *reinterpret_cast<uint8_t *>(ptr);
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}

void make_icmp_packet(char *packet, uint16_t seq) {
  memset(packet, 0, 64);
  icmphdr *icmp = reinterpret_cast<icmphdr *>(packet);
  icmp->type = ICMP_ECHO;
  icmp->code = 0;
  icmp->un.echo.id = htons(getpid() & 0xFFFF);
  icmp->un.echo.sequence = htons(seq);
  icmp->checksum = 0;
  icmp->checksum = checksum(packet, 64);
}

int main() {
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    perror("socket");
    return 1;
  }

  // Set non-blocking socket for recv
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  auto start_time = std::chrono::steady_clock::now();
  std::atomic<int> sent_count(0);

  char packet[64];
  sockaddr_in dest{};
  dest.sin_family = AF_INET;

  uint32_t ip_int = 0;  // start from 0.0.0.0
  const uint32_t max_ip = 0xFFFFFFFF;

  while (true) {
    dest.sin_addr.s_addr = htonl(ip_int);

    make_icmp_packet(packet, ip_int & 0xFFFF);

    ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                          reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
    if (sent > 0) sent_count++;

    ip_int++;
    if (ip_int == 0) break;  // wrapped around (overflow)

    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_time).count();
    if (elapsed > 1.0) break;
  }

  std::cout << "Sent " << sent_count.load() << " ICMP packets in 1 second\n";

  close(sock);
  return 0;
}

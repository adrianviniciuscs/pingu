#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <fcntl.h>

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

  // Set socket non-blocking for recv
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

  const char *base_ip = "192.168.1.";
  const int start_ip = 1;
  const int end_ip = 254;

  std::vector<bool> replied(end_ip - start_ip + 1, false);
  int replies = 0;

  auto start_time = std::chrono::steady_clock::now();

  // Send all pings asap
  for (int i = start_ip; i <= end_ip; ++i) {
    char ip[16];
    snprintf(ip, sizeof(ip), "%s%d", base_ip, i);

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &dest.sin_addr);

    char packet[64];
    make_icmp_packet(packet, i);

    ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                          reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
    if (sent <= 0) {
      perror("sendto");
    }
  }

  // Listen for replies for 1 second
  while (true) {
    auto now = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(now - start_time).count();
    if (elapsed > 1.0) break;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 10000;  // 10ms

    int ret = select(sock + 1, &readfds, nullptr, nullptr, &tv);
    if (ret > 0 && FD_ISSET(sock, &readfds)) {
      char buffer[1024];
      sockaddr_in reply_addr{};
      socklen_t addr_len = sizeof(reply_addr);

      ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                             reinterpret_cast<sockaddr *>(&reply_addr), &addr_len);
      if (len <= 0) continue;

      iphdr *ip = reinterpret_cast<iphdr *>(buffer);
      int ip_header_len = ip->ihl * 4;
      icmphdr *icmp = reinterpret_cast<icmphdr *>(buffer + ip_header_len);

      if (icmp->type == ICMP_ECHOREPLY &&
          ntohs(icmp->un.echo.id) == (getpid() & 0xFFFF)) {
        uint16_t seq = ntohs(icmp->un.echo.sequence);
        if (seq >= start_ip && seq <= end_ip && !replied[seq - start_ip]) {
          replied[seq - start_ip] = true;
          replies++;
          std::cout << "Reply from " << inet_ntoa(reply_addr.sin_addr) << "\n";
        }
      }
    }
  }

  std::cout << "Total replies in 1 second: " << replies << "\n";
  close(sock);
  return 0;
}


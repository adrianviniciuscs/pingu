#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <unordered_set>

uint16_t checksum(void* data, int len) {
    uint16_t* ptr = static_cast<uint16_t*>(data);
    uint32_t sum = 0;
    for (; len > 1; len -= 2) sum += *ptr++;
    if (len == 1) sum += *reinterpret_cast<uint8_t*>(ptr);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

void make_icmp_packet(char* packet, uint16_t seq) {
    memset(packet, 0, 64);
    icmphdr* icmp = reinterpret_cast<icmphdr*>(packet);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(getpid() & 0xFFFF);
    icmp->un.echo.sequence = htons(seq);
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, 64);
}

int main() {
    const char* base_ip = "10.241.";
    const int start_host = 1;
    const int end_host = 254;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Non-blocking socket to poll replies without blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    std::unordered_set<uint16_t> awaiting_replies;

    char packet[64];
    sockaddr_in dest{};
    dest.sin_family = AF_INET;

    auto start_time = std::chrono::steady_clock::now();

    uint16_t sequence = 1;
    int sent_count = 0;
    int reply_count = 0;

    while (true) {
        for (int host = start_host; host <= end_host; ++host) {
            std::string ip_str = std::string(base_ip) + std::to_string(host);
            inet_pton(AF_INET, ip_str.c_str(), &dest.sin_addr);

            make_icmp_packet(packet, sequence);
            ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                                  reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
            if (sent > 0) {
                awaiting_replies.insert(sequence);
                ++sent_count;
            }
            ++sequence;

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration<double>(now - start_time).count() > 1.0)
                break;
        }
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - start_time).count() > 1.0)
            break;

        while (true) {
            char buffer[1024];
            sockaddr_in reply_addr{};
            socklen_t addr_len = sizeof(reply_addr);
            ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0,
                                   reinterpret_cast<sockaddr*>(&reply_addr), &addr_len);
            if (len <= 0) break; // no more replies

            iphdr* ip = reinterpret_cast<iphdr*>(buffer);
            int ip_header_len = ip->ihl * 4;
            icmphdr* icmp = reinterpret_cast<icmphdr*>(buffer + ip_header_len);

            if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == (getpid() & 0xFFFF)) {
                uint16_t seq = ntohs(icmp->un.echo.sequence);
                if (awaiting_replies.erase(seq)) {
                    ++reply_count;
                    std::cout << "Reply from " << inet_ntoa(reply_addr.sin_addr) << std::endl;
                }
            }
        }
    }

    std::cout << "Sent packets: " << sent_count << "\n";
    std::cout << "Replies received: " << reply_count << "\n";

    close(sock);
    return 0;
}

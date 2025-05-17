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
#include <thread>
#include <mutex>
#include <vector>
#include <signal.h>

// Configurações para modo turbo
const int PACKET_SIZE = 28;         // Mínimo absoluto (só header)
const int NUM_SENDER_THREADS = 16;  // Maximizar threads
const bool SKIP_PRIVATE_RANGES = true;
const uint32_t START_IP = 1;        // Começa do 0.0.0.1

std::mutex cout_mutex;
std::atomic<bool> should_stop{false};
std::atomic<uint64_t> sent_count{0};
std::atomic<uint64_t> received_count{0};
std::atomic<uint32_t> current_ip{START_IP};

// Handler para sinais
void signal_handler(int signal) {
    std::cout << "\nInterrompendo...\n";
    should_stop = true;
}

// Checksum ultra-otimizado
uint16_t checksum(void *data, int len) {
    uint16_t *ptr = static_cast<uint16_t *>(data);
    uint32_t sum = 0;
    
    for (; len > 1; len -= 2) {
        sum += *ptr++;
    }
    
    if (len == 1) {
        sum += *reinterpret_cast<uint8_t *>(ptr);
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

// ICMP packet maker turbo
void make_icmp_packet(char *packet) {
    // Limpa só o necessário
    memset(packet, 0, PACKET_SIZE);
    icmphdr *icmp = reinterpret_cast<icmphdr *>(packet);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    
    // Usa valor fixo para economizar CPU
    icmp->un.echo.id = htons(0x1234);
    icmp->un.echo.sequence = htons(0x5678);
    
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, PACKET_SIZE);
}

// Filtro de IP ultra rápido
bool should_skip_ip(uint32_t ip) {
    // Ignora IPs especiais/reservados
    if (ip == 0) return true;                               // 0.0.0.0
    if ((ip & 0xFF000000) == 0x7F000000) return true;       // 127.0.0.0/8
    if ((ip & 0xF0000000) == 0xE0000000) return true;       // 224.0.0.0/4 (Multicast)
    if ((ip & 0xFF000000) == 0xFF000000) return true;       // 255.0.0.0/8 (Broadcast)
    
    // Ignora faixas privadas comuns
    if (SKIP_PRIVATE_RANGES) {
        if ((ip & 0xFF000000) == 0x0A000000) return true;   // 10.0.0.0/8
        if ((ip & 0xFFF00000) == 0xAC100000) return true;   // 172.16.0.0/12
        if ((ip & 0xFFFF0000) == 0xC0A80000) return true;   // 192.168.0.0/16
    }
    
    return false;
}

// Thread de envio turbinada
void turbo_sender(int sock) {
    // Pré-aloca o buffer do pacote
    char packet[PACKET_SIZE];
    make_icmp_packet(packet);
    
    // Pré-configura o endereço de destino
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    
    while (!should_stop) {
        // Pega o próximo IP para processar (com incremento atômico)
        uint32_t ip = current_ip.fetch_add(1);
        
        // Se chegou ao fim do espaço de IPs
        if (ip == 0) break;
        
        // Pula IPs que devem ser ignorados
        if (should_skip_ip(ip)) continue;
        
        // Configura o destino
        dest.sin_addr.s_addr = htonl(ip);
        
        // Envia sem verificação de erro para máxima performance
        sendto(sock, packet, sizeof(packet), 0,
               reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        
        sent_count++;
    }
}

// Thread para receber respostas
void response_receiver(int sock) {
    char buffer[1500];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    
    while (!should_stop) {
        // Recebe pacotes o mais rápido possível
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                   (struct sockaddr*)&sender, &sender_len);
        
        if (received > 0) {
            // Verifica se é uma resposta ICMP Echo Reply
            struct ip* ip_header = (struct ip*)buffer;
            int ip_header_len = ip_header->ip_hl * 4;
            
            if (received >= ip_header_len + sizeof(icmphdr)) {
                struct icmphdr* icmp = (struct icmphdr*)(buffer + ip_header_len);
                
                if (icmp->type == ICMP_ECHOREPLY && 
                    ntohs(icmp->un.echo.id) == 0x1234) {
                    received_count++;
                    
                    // Opcional: para debug/logging em baixo volume
                    // std::string ip_str = inet_ntoa(sender.sin_addr);
                    // std::lock_guard<std::mutex> lock(cout_mutex);
                    // std::cout << "Resposta de " << ip_str << std::endl;
                }
            }
        }
    }
}

int main() {
    // Configura handler para Ctrl+C
    signal(SIGINT, signal_handler);
    
    std::cout << "╔═════════════════════════════════════╗\n";
    std::cout << "║  PINGU TURBO EDITION - CHALLENGE 1s ║\n";
    std::cout << "╚═════════════════════════════════════╝\n";
    
    // Cria socket raw
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Erro ao criar socket");
        return 1;
    }
    
    // Configura o socket como não-bloqueante
    fcntl(sock, F_SETFL, O_NONBLOCK);
    
    // Aumenta os buffers do socket ao máximo
    int buffer_size = 32 * 1024 * 1024; // 32MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
    
    // Inicia thread de recepção
    std::thread receiver_thread(response_receiver, sock);
    
    // Prepara as threads de envio
    std::vector<std::thread> sender_threads;
    for (int i = 0; i < NUM_SENDER_THREADS; i++) {
        sender_threads.emplace_back(turbo_sender, sock);
    }
    
    // Cronômetro: exatamente 1 segundo
    auto start_time = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    should_stop = true;
    
    // Junta as threads de envio
    for (auto& t : sender_threads) {
        t.join();
    }
    
    // Aguarda um pouco mais para coletar respostas finais
    std::cout << "Aguardando respostas finais..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Finaliza a thread de recepção
    receiver_thread.join();
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Mostra resultados finais
    uint64_t total_sent = sent_count.load();
    uint64_t total_received = received_count.load();
    double packets_per_second = total_sent * 1000.0 / duration.count();
    double response_rate = (total_sent > 0) ? (total_received * 100.0 / total_sent) : 0.0;
    uint32_t last_ip = current_ip.load();
    
    std::cout << "\n╔═══════════════════════════════════════════════════╗\n";
    std::cout << "║                RESULTADOS FINAIS                  ║\n";
    std::cout << "╠═══════════════════════════════════════════════════╣\n";
    printf("║ ⏱️  Tempo decorrido:  %6d ms                      ║\n", (int)duration.count());
    printf("║ 🚀 Pacotes enviados:  %10lu                     ║\n", total_sent);
    printf("║ 📥 Respostas:         %10lu                     ║\n", total_received);
    printf("║ 🔥 Taxa de envio:     %10.1f pkts/s              ║\n", packets_per_second);
    printf("║ ✅ Taxa de resposta:  %10.2f%%                     ║\n", response_rate);
    printf("║ 🌐 Último IP:         %3d.%3d.%3d.%3d               ║\n", 
           ((last_ip >> 24) & 0xFF), ((last_ip >> 16) & 0xFF), 
           ((last_ip >> 8) & 0xFF), (last_ip & 0xFF));
    std::cout << "╚═══════════════════════════════════════════════════╝\n";
    
    close(sock);
    return 0;
}
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
#include <ifaddrs.h>
#include <netdb.h>
#include <string>

// Configurações para modo custom
const int PACKET_SIZE = 28;         // Mínimo absoluto (só header)
const int NUM_SENDER_THREADS = 16;  // Mais threads para redes maiores
const bool SHOW_REPLIES = true;     // Exibir IPs que responderam

std::mutex cout_mutex;
std::atomic<bool> should_stop{false};
std::atomic<uint64_t> sent_count{0};
std::atomic<uint64_t> received_count{0};
std::atomic<uint32_t> current_ip{0};  // Definido posteriormente
uint32_t end_ip{0};                   // Limite da faixa de scan

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

// Converte string IP para uint32_t
uint32_t ip_to_uint(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str.c_str(), &addr) == 0) {
        throw std::runtime_error("IP inválido: " + ip_str);
    }
    return ntohl(addr.s_addr);
}

// Converte CIDR para máscara
uint32_t cidr_to_mask(int cidr) {
    if (cidr < 0 || cidr > 32) {
        throw std::runtime_error("CIDR inválido: " + std::to_string(cidr));
    }
    return cidr == 0 ? 0 : (~0U << (32 - cidr));
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
        if (ip > end_ip) break;
        
        // Configura o destino
        dest.sin_addr.s_addr = htonl(ip);
        
        // Envia sem verificação de erro para máxima performance
        sendto(sock, packet, sizeof(packet), 0,
               reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        
        sent_count++;
    }
}

// Função para processar respostas de forma síncrona
void process_responses(int sock) {
    char buffer[1500];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    
    // Define um timeout para o recvfrom
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    while (!should_stop) {
        // Tenta receber pacotes
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                   (struct sockaddr*)&sender, &sender_len);
        
        if (received <= 0) {
            // Timeout ou erro
            continue;
        }
        
        // Verifica se é uma resposta ICMP Echo Reply
        struct ip* ip_header = (struct ip*)buffer;
        int ip_header_len = ip_header->ip_hl * 4;
        
        if (received >= ip_header_len + sizeof(icmphdr)) {
            struct icmphdr* icmp = (struct icmphdr*)(buffer + ip_header_len);
            
            if (icmp->type == ICMP_ECHOREPLY && 
                ntohs(icmp->un.echo.id) == 0x1234) {
                received_count++;
                
                // Exibe o IP que respondeu
                if (SHOW_REPLIES) {
                    std::string ip_str = inet_ntoa(sender.sin_addr);
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "✅ Resposta de: " << ip_str << std::endl;
                }
            }
        }
    }
}

int main(int argc, char* argv[]) {
    // Configura handler para Ctrl+C
    signal(SIGINT, signal_handler);
    
    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║        PINGU MAN/WAN CUSTOM NETWORK SCAN     ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n\n";
    
    // Variáveis para a rede a ser escaneada
    std::string network_str;
    int cidr = 24;  // Padrão /24
    
    if (argc == 2 || argc == 3) {
        // Formato esperado: ./pingu_man 192.168.1.0/24 ou ./pingu_man 192.168.1.0 24
        network_str = argv[1];
        
        // Verificar se o formato é IP/CIDR
        size_t slash_pos = network_str.find('/');
        if (slash_pos != std::string::npos) {
            cidr = std::stoi(network_str.substr(slash_pos + 1));
            network_str = network_str.substr(0, slash_pos);
        } else if (argc == 3) {
            cidr = std::stoi(argv[2]);
        }
    } else {
        std::cout << "Por favor, informe a rede a ser escaneada:\n";
        std::cout << "Rede (ex: 10.0.0.0): ";
        std::cin >> network_str;
        std::cout << "CIDR (ex: 24 para /24): ";
        std::cin >> cidr;
    }
    
    try {
        // Converte IP base da rede para uint32_t
        uint32_t base_ip = ip_to_uint(network_str);
        uint32_t mask = cidr_to_mask(cidr);
        
        // Calcula o primeiro e último IP da rede
        uint32_t network = base_ip & mask;
        uint32_t broadcast = network | (~mask);
        
        // Define faixa a ser escaneada
        current_ip = network + 1;
        end_ip = broadcast - 1;
        
        // Converte para strings para exibição
        char start_ip_str[INET_ADDRSTRLEN];
        struct in_addr start_addr;
        start_addr.s_addr = htonl(current_ip.load());
        inet_ntop(AF_INET, &start_addr, start_ip_str, INET_ADDRSTRLEN);
        
        char end_ip_str[INET_ADDRSTRLEN];
        struct in_addr end_addr;
        end_addr.s_addr = htonl(end_ip);
        inet_ntop(AF_INET, &end_addr, end_ip_str, INET_ADDRSTRLEN);
        
        char network_addr_str[INET_ADDRSTRLEN];
        struct in_addr net_addr;
        net_addr.s_addr = htonl(network);
        inet_ntop(AF_INET, &net_addr, network_addr_str, INET_ADDRSTRLEN);
        
        char broadcast_str[INET_ADDRSTRLEN];
        struct in_addr bcast_addr;
        bcast_addr.s_addr = htonl(broadcast);
        inet_ntop(AF_INET, &bcast_addr, broadcast_str, INET_ADDRSTRLEN);
        
        // Calcula o total de IPs
        uint32_t total_ips = end_ip - current_ip + 1;
        
        // Exibe informações da rede
        std::cout << "Informações da rede:\n";
        std::cout << "- Rede: " << network_addr_str << "/" << cidr << std::endl;
        std::cout << "- Broadcast: " << broadcast_str << std::endl;
        std::cout << "- Faixa de scan: " << start_ip_str << " até " << end_ip_str << std::endl;
        std::cout << "- Total de IPs: " << total_ips << std::endl;
        std::cout << "- Threads: " << NUM_SENDER_THREADS << std::endl;
        
        // Cria socket raw
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("Erro ao criar socket");
            return 1;
        }
        
        // Configura o socket como não-bloqueante
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        // Aumenta os buffers do socket
        int buffer_size = 8 * 1024 * 1024; // 8MB para redes maiores
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        
        std::cout << "\nIniciando escaneamento em 1 segundo...\n" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Prepara as threads de envio
        std::vector<std::thread> sender_threads;
        
        // Iniciar cronômetro para controlar o tempo exato de 1 segundo
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Inicia as threads de envio
        for (int i = 0; i < NUM_SENDER_THREADS; i++) {
            sender_threads.emplace_back(turbo_sender, sock);
        }
        
        // Aguarda exatamente 1 segundo e então para o envio
        std::this_thread::sleep_for(std::chrono::seconds(1));
        should_stop = true;
        
        // Junta as threads de envio
        for (auto& t : sender_threads) {
            t.join();
        }
        
        // Registra o fim do tempo de envio
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Processa respostas de forma síncrona após o término do envio
        std::cout << "\nProcessando respostas..." << std::endl;
        
        // Define um tempo limite para processar as respostas (500ms)
        auto process_start = std::chrono::high_resolution_clock::now();
        auto process_timeout = std::chrono::milliseconds(500);
        should_stop = false;
        
        while (!should_stop) {
            process_responses(sock);
            
            // Verifica se o tempo de processamento chegou ao limite
            auto now = std::chrono::high_resolution_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - process_start) >= process_timeout) {
                should_stop = true;
            }
        }
        
        // Mostra resultados finais
        uint64_t total_sent = sent_count.load();
        uint64_t total_received = received_count.load();
        double packets_per_second = total_sent * 1000.0 / duration.count();
        double response_rate = (total_sent > 0) ? (total_received * 100.0 / total_sent) : 0.0;
        
        std::cout << "\n╔═══════════════════════════════════════════════════╗\n";
        std::cout << "║                RESULTADOS FINAIS                  ║\n";
        std::cout << "╠═══════════════════════════════════════════════════╣\n";
        printf("║ ⏱️  Tempo decorrido:  %6d ms                      ║\n", (int)duration.count());
        printf("║ 🚀 Pacotes enviados:  %10lu                     ║\n", total_sent);
        printf("║ 📥 Respostas:         %10lu                     ║\n", total_received);
        printf("║ 🔥 Taxa de envio:     %10.1f pkts/s              ║\n", packets_per_second);
        printf("║ ✅ Taxa de resposta:  %10.2f%%                     ║\n", response_rate);
        std::cout << "╚═══════════════════════════════════════════════════╝\n";
        
        close(sock);
    }
    catch(const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
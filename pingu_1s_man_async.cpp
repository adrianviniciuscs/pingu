#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <iomanip>    
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <atomic>
#include <thread>
#include <mutex>
#include <vector>
#include <queue>
#include <signal.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <string>
#include <deque>

// Configurações otimizadas
const int PACKET_SIZE = 28;             // Tamanho mínimo do pacote
const int NUM_SENDER_THREADS = 16;      // Threads de envio
const int NUM_RECEIVER_THREADS = 2;     // Threads de recepção
const int RESPONSE_QUEUE_SIZE = 10000;  // Tamanho do buffer de respostas
const bool SHOW_LIVE_RESPONSES = false; // Mostrar respostas em tempo real (desligar para máx velocidade)

// Estrutura para armazenar respostas recebidas
struct IcmpResponse {
    struct in_addr src_addr;
    uint16_t seq;
    double rtt_ms;
};

// Variáveis globais compartilhadas
std::mutex cout_mutex;
std::atomic<bool> should_stop{false};
std::atomic<uint64_t> sent_count{0};
std::atomic<uint64_t> received_count{0};
std::atomic<uint32_t> current_ip{0};
uint32_t end_ip{0};

// Fila thread-safe para armazenar respostas para processamento assíncrono
std::deque<IcmpResponse> response_queue;
std::mutex queue_mutex;
std::atomic<bool> processor_running{false};

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

// Thread de envio ultra rápido sem bloqueios
void turbo_sender(int sock) {
    // Pré-aloca o buffer do pacote e reutiliza
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

// Thread dedicada para receber pacotes (sem processar)
void response_receiver(int sock) {
    char buffer[1500];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    auto start_time = std::chrono::steady_clock::now();
    
    // Configuração para select()
    fd_set readfds;
    struct timeval tv;
    
    while (!should_stop) {
        // Configurar select para espera não-bloqueante
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 1000; // 1ms timeout
        
        int ready = select(sock + 1, &readfds, nullptr, nullptr, &tv);
        
        if (ready <= 0) continue; // Timeout ou erro
        
        // Recebe pacote sem bloqueio
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0, 
                                  (struct sockaddr*)&sender, &sender_len);
        
        if (received <= 0) continue;
        
        // Processamento rápido apenas para verificar se é uma resposta válida
        struct ip* ip_header = (struct ip*)buffer;
        int ip_header_len = ip_header->ip_hl * 4;
        
        if (received < ip_header_len + sizeof(icmphdr)) continue;
        
        struct icmphdr* icmp = (struct icmphdr*)(buffer + ip_header_len);
        
        if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == 0x1234) {
            // Incrementa contador atômico
            received_count++;
            
            // Calcular RTT
            auto now = std::chrono::steady_clock::now();
            double rtt_ms = std::chrono::duration<double, std::milli>(now - start_time).count();
            
            // Em vez de processar aqui, coloca na fila para processamento assíncrono
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                // Limitar tamanho da fila para evitar uso excessivo de memória
                if (response_queue.size() < RESPONSE_QUEUE_SIZE) {
                    IcmpResponse resp;
                    resp.src_addr = sender.sin_addr;
                    resp.seq = ntohs(icmp->un.echo.sequence);
                    resp.rtt_ms = rtt_ms;
                    response_queue.push_back(resp);
                }
            }
        }
    }
}

// Thread que processa respostas da fila em background
void response_processor() {
    processor_running = true;
    std::vector<IcmpResponse> batch;
    batch.reserve(100); // Processar em pequenos lotes
    
    while (!should_stop || !response_queue.empty()) {
        // Dormir brevemente entre processamentos para dar prioridade ao envio
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        
        // Pegar lote da fila
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            
            // Limitar o número de itens processados por vez
            size_t batch_size = std::min(response_queue.size(), (size_t)100);
            
            for (size_t i = 0; i < batch_size; i++) {
                batch.push_back(response_queue.front());
                response_queue.pop_front();
            }
        }
        
        // Processar lote (fora do lock)
        if (!batch.empty() && SHOW_LIVE_RESPONSES) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            for (const auto& resp : batch) {
                std::cout << "✅ Resposta de: " << inet_ntoa(resp.src_addr)
                          << " tempo=" << std::fixed << std::setprecision(2) << resp.rtt_ms << "ms" 
                          << std::endl;
            }
        }
        
        batch.clear();
    }
    
    processor_running = false;
}

// Thread para exibir estatísticas em tempo real sem prejudicar o desempenho
void stats_thread() {
    uint64_t last_sent = 0;
    uint64_t last_recv = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!should_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last_time).count();
        
        uint64_t curr_sent = sent_count.load();
        uint64_t curr_recv = received_count.load();
        
        uint64_t sent_diff = curr_sent - last_sent;
        uint64_t recv_diff = curr_recv - last_recv;
        
        double send_rate = sent_diff / elapsed;
        double recv_rate = recv_diff / elapsed;
        
        // Tamanho atual da fila de respostas
        size_t queue_size;
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            queue_size = response_queue.size();
        }
        
        // Calcular IP atual em formato legível
        uint32_t ip = current_ip.load();
        
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "Enviados: " << curr_sent 
                      << " (" << std::fixed << std::setprecision(1) << send_rate << "/s) | "
                      << "Recebidos: " << curr_recv
                      << " (" << recv_rate << "/s) | "
                      << "Fila: " << queue_size << " | "
                      << "IP: " << ((ip >> 24) & 0xFF) << "."
                      << ((ip >> 16) & 0xFF) << "."
                      << ((ip >> 8) & 0xFF) << "."
                      << (ip & 0xFF)
                      << "\r" << std::flush;
        }
        
        last_sent = curr_sent;
        last_recv = curr_recv;
        last_time = now;
    }
}

int main(int argc, char* argv[]) {
    // Configura handler para Ctrl+C
    signal(SIGINT, signal_handler);
    
    std::cout << "╔═══════════════════════════════════════════════════════╗\n";
    std::cout << "║      PINGU ASYNC EDITION - PERFORMANCE EXTREMA        ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════╝\n\n";
    
    // Variáveis para a rede a ser escaneada
    std::string network_str;
    int cidr = 24;  // Padrão /24
    
    if (argc == 2 || argc == 3) {
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
        
        // Informações da rede
        std::cout << "Preparando para escanear rede " << network_str << "/" << cidr << std::endl;
        std::cout << "Total de IPs: " << (end_ip - current_ip + 1) << std::endl;
        
        // Cria socket raw
        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock < 0) {
            perror("Erro ao criar socket");
            return 1;
        }
        
        // Configura o socket como não-bloqueante
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        // Aumenta os buffers do socket
        int buffer_size = 16 * 1024 * 1024; // 16MB
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        
        std::cout << "Buffers de socket: " << (buffer_size / 1024 / 1024) << "MB" << std::endl;
        std::cout << "Iniciando scan com processamento assíncrono...\n\n";
        
        // Thread de estatísticas
        std::thread stats_thread_obj(stats_thread);
        
        // Threads de processamento de respostas (baixa prioridade)
        std::thread processor_thread(response_processor);
        
        // Threads de recepção (prioridade média)
        std::vector<std::thread> receiver_threads;
        for (int i = 0; i < NUM_RECEIVER_THREADS; i++) {
            receiver_threads.emplace_back(response_receiver, sock);
        }
        
        // Inicia cronômetro
        auto start_time = std::chrono::steady_clock::now();
        
        // Threads de envio (alta prioridade)
        std::vector<std::thread> sender_threads;
        for (int i = 0; i < NUM_SENDER_THREADS; i++) {
            sender_threads.emplace_back(turbo_sender, sock);
        }
        
        // Tempo de execução exatamente 1 segundo
        std::this_thread::sleep_for(std::chrono::seconds(1));
        should_stop = true;
        
        // Junta as threads de envio
        for (auto& t : sender_threads) {
            t.join();
        }
        
        // Captura o tempo após o envio concluído
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Aguarda mais um pouco para coletar respostas atrasadas
        std::cout << "\nEnvio concluído. Aguardando respostas finais..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        // Junta as threads restantes
        for (auto& t : receiver_threads) {
            t.join();
        }
        
        processor_thread.join();
        stats_thread_obj.join();
        
        // Mostra resultados finais
        uint64_t total_sent = sent_count.load();
        uint64_t total_received = received_count.load();
        double packets_per_second = total_sent * 1000.0 / duration.count();
        double response_rate = (total_sent > 0) ? (total_received * 100.0 / total_sent) : 0.0;
        
        std::cout << "\n╔═══════════════════════════════════════════════════════╗\n";
        std::cout << "║                RESULTADOS FINAIS                       ║\n";
        std::cout << "╠═══════════════════════════════════════════════════════╣\n";
        printf("║ ⏱️  Tempo decorrido:    %6d ms                         ║\n", (int)duration.count());
        printf("║ 🚀 Pacotes enviados:  %10lu                         ║\n", total_sent);
        printf("║ 📥 Respostas:         %10lu                         ║\n", total_received);
        printf("║ 🔥 Taxa de envio:     %10.1f pkts/s                  ║\n", packets_per_second);
        printf("║ ✅ Taxa de resposta:   %9.2f%%                          ║\n", response_rate);
        printf("║ 🌐 Último IP: %3d.%3d.%3d.%3d                            ║\n", 
               ((current_ip.load() >> 24) & 0xFF), ((current_ip.load() >> 16) & 0xFF), 
               ((current_ip.load() >> 8) & 0xFF), (current_ip.load() & 0xFF));
        std::cout << "╚═══════════════════════════════════════════════════════╝\n";
        
        close(sock);
    }
    catch(const std::exception& e) {
        std::cerr << "Erro: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
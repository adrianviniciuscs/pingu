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
#include <map>
#include <queue>
#include <condition_variable>
#include <iomanip>
#include <signal.h>

// Configurações ajustáveis
const int PACKET_SIZE = 56;  // Menor tamanho para maior eficiência
const int TIMEOUT_SECONDS = 10;
const bool SKIP_PRIVATE_RANGES = true;
const int NUM_SENDER_THREADS = 4;  // Usar múltiplas threads de envio
const bool ENABLE_BATCH_PROCESSING = true;  // Processar em lotes

struct PingResult {
    std::string ip;
    bool received;
    double rtt_ms;
};

std::mutex cout_mutex;
std::queue<PingResult> results_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;

std::atomic<bool> should_stop{false};
std::atomic<uint64_t> sent_count{0};
std::atomic<uint64_t> received_count{0};
std::atomic<uint32_t> current_ip{1};  // IP compartilhado entre threads

// Rotina para lidar com Ctrl+C
void signal_handler(int signal) {
    std::cout << "\nRecebido sinal de interrupção. Finalizando...\n";
    should_stop = true;
}

// Função melhorada de checksum
uint16_t checksum(void *data, int len) {
    uint16_t *ptr = static_cast<uint16_t *>(data);
    uint32_t sum = 0;
    
    // Soma em blocos de 16 bits
    for (; len > 1; len -= 2) {
        sum += *ptr++;
    }
    
    if (len == 1) {
        sum += *reinterpret_cast<uint8_t *>(ptr);
    }
    
    // Adiciona os carries
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

// Função para criar um pacote ICMP mais eficiente
void make_icmp_packet(char *packet, uint16_t seq, uint16_t identifier) {
    memset(packet, 0, PACKET_SIZE);
    icmphdr *icmp = reinterpret_cast<icmphdr *>(packet);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htons(identifier);
    icmp->un.echo.sequence = htons(seq);
    
    // Adicionar timestamp no payload para calcular RTT
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    uint64_t timestamp = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    memcpy(packet + sizeof(icmphdr), &timestamp, sizeof(timestamp));
    
    icmp->checksum = 0;
    icmp->checksum = checksum(packet, PACKET_SIZE);
}

// Verificação otimizada de IPs privados
bool is_private_ip(uint32_t ip) {
    // Já está em ordem de host
    uint32_t host_order_ip = ip;
    
    // Checagens rápidas para os ranges mais comuns
    if (host_order_ip == 0) return true;  // 0.0.0.0
    if ((host_order_ip & 0xFF000000) == 0x0A000000) return true;  // 10.0.0.0/8
    if ((host_order_ip & 0xFFF00000) == 0xAC100000) return true;  // 172.16.0.0/12
    if ((host_order_ip & 0xFFFF0000) == 0xC0A80000) return true;  // 192.168.0.0/16
    if ((host_order_ip & 0xFF000000) == 0x7F000000) return true;  // 127.0.0.0/8
    if ((host_order_ip & 0xF0000000) == 0xE0000000) return true;  // 224.0.0.0/4 Multicast
    if ((host_order_ip & 0xFFFF0000) == 0xA9FE0000) return true;  // 169.254.0.0/16
    
    return false;
}

// Thread para receber as respostas ICMP de forma mais eficiente
void receive_replies(int sock, uint16_t identifier) {
    char buffer[1500];  // Buffer para pacotes de resposta
    
    fd_set readfds;
    struct timeval tv;
    
    while (!should_stop) {
        // Configurar select para monitorar o socket
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        
        // Timeout curto para não bloquear muito tempo
        tv.tv_sec = 0;
        tv.tv_usec = 10000;  // 10ms
        
        int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (ready < 0) {
            if (errno != EINTR) {  // Ignorar erros por interrupção
                perror("select");
            }
            continue;
        } else if (ready == 0) {
            continue;  // Timeout, nada para ler
        }
        
        // Há dados para ler
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        
        ssize_t received = recvfrom(sock, buffer, sizeof(buffer), 0,
                                   (struct sockaddr*)&sender, &sender_len);
                                   
        if (received <= 0) continue;
        
        // Processamento eficiente do pacote
        struct ip *ip_header = (struct ip*)buffer;
        int ip_header_len = ip_header->ip_hl * 4;
        
        // Verifica se temos um cabeçalho ICMP válido
        if (received < ip_header_len + sizeof(icmphdr)) continue;
        
        struct icmphdr *icmp = (struct icmphdr*)(buffer + ip_header_len);
        
        // Verifica se é uma resposta ECHO REPLY para nossos pacotes
        if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == identifier) {
            // Extrai o timestamp original para calcular RTT
            if (received >= ip_header_len + sizeof(icmphdr) + sizeof(uint64_t)) {
                uint64_t send_timestamp;
                memcpy(&send_timestamp, buffer + ip_header_len + sizeof(icmphdr), sizeof(send_timestamp));
                
                auto now = std::chrono::steady_clock::now().time_since_epoch();
                uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
                double rtt_ms = (now_us - send_timestamp) / 1000.0;
                
                // Registra o resultado
                PingResult result;
                result.ip = inet_ntoa(sender.sin_addr);
                result.received = true;
                result.rtt_ms = rtt_ms;
                
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    results_queue.push(result);
                }
                queue_cv.notify_one();
                
                received_count++;
            }
        }
    }
}

// Thread otimizada para processar e exibir resultados
void process_results() {
    const size_t BATCH_SIZE = 10;  // Processar vários resultados de uma vez
    std::vector<PingResult> batch;
    batch.reserve(BATCH_SIZE);
    
    while (!should_stop || !results_queue.empty()) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (results_queue.empty()) {
                queue_cv.wait_for(lock, std::chrono::milliseconds(100));
                continue;
            }
            
            // Processar em lotes para melhor performance
            if (ENABLE_BATCH_PROCESSING) {
                size_t count = 0;
                while (!results_queue.empty() && count < BATCH_SIZE) {
                    batch.push_back(results_queue.front());
                    results_queue.pop();
                    count++;
                }
            } else {
                // Processamento individual
                batch.push_back(results_queue.front());
                results_queue.pop();
            }
        }
        
        // Exibe os resultados
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            for (const auto& result : batch) {
                std::cout << "Reply from " << std::left << std::setw(15) << result.ip 
                          << " time=" << std::fixed << std::setprecision(2) << result.rtt_ms << "ms" 
                          << std::endl;
            }
        }
        
        batch.clear();
    }
}

// Thread de envio
void send_pings(int sock, uint16_t identifier) {
    char packet[PACKET_SIZE];
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    
    while (!should_stop) {
        // Pega o próximo IP para processar
        uint32_t ip_int = current_ip.fetch_add(1);
        
        // Se chegou ao fim do espaço de IPs
        if (ip_int == 0) {
            break;
        }
        
        // Pula IPs privados/inválidos
        if (SKIP_PRIVATE_RANGES && is_private_ip(ip_int)) {
            continue;
        }
        
        // Configura o destino
        dest.sin_addr.s_addr = htonl(ip_int);
        
        // Cria o pacote ICMP
        make_icmp_packet(packet, ip_int & 0xFFFF, identifier);
        
        // Envia o pacote
        ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                             reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
        
        if (sent > 0) {
            sent_count++;
        }
    }
}

// Thread para exibir estatísticas periodicamente
void stats_thread() {
    uint64_t last_sent = 0;
    uint64_t last_received = 0;
    auto last_time = std::chrono::steady_clock::now();
    
    while (!should_stop) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - last_time).count();
        
        uint64_t current_sent = sent_count.load();
        uint64_t current_received = received_count.load();
        
        uint64_t sent_diff = current_sent - last_sent;
        uint64_t received_diff = current_received - last_received;
        
        // Taxa por segundo
        double send_rate = sent_diff / elapsed;
        double receive_rate = received_diff / elapsed;
        
        {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << "--- Estatísticas: " 
                      << current_sent << " enviados (" << std::fixed << std::setprecision(1) << send_rate << "/s), " 
                      << current_received << " recebidos (" << receive_rate << "/s) - "
                      << (current_sent > 0 ? (current_received * 100.0 / current_sent) : 0.0)
                      << "% sucesso - IP atual: "
                      << ((current_ip.load() >> 24) & 0xFF) << "."
                      << ((current_ip.load() >> 16) & 0xFF) << "."
                      << ((current_ip.load() >> 8) & 0xFF) << "."
                      << (current_ip.load() & 0xFF)
                      << " ---" << std::endl;
        }
        
        last_sent = current_sent;
        last_received = current_received;
        last_time = now;
    }
}

int main(int argc, char* argv[]) {
    // Configurar handler de sinal para Ctrl+C
    signal(SIGINT, signal_handler);
    
    // Cria o socket raw
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }
    
    // Configura o socket como não-bloqueante
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Aumenta os buffers do socket significativamente
    int sndbuf = 8 * 1024 * 1024; // 8MB
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int rcvbuf = 8 * 1024 * 1024; // 8MB
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    // Identificador único
    uint16_t identifier = getpid() & 0xFFFF;
    
    std::cout << "Iniciando pingu otimizado com " << NUM_SENDER_THREADS << " threads de envio\n";
    
    // Inicia threads de recepção e processamento
    std::thread receiver_thread(receive_replies, sock, identifier);
    std::thread processor_thread(process_results);
    std::thread stats_thread_obj(stats_thread);
    
    // Vetor de threads de envio
    std::vector<std::thread> sender_threads;
    for (int i = 0; i < NUM_SENDER_THREADS; i++) {
        sender_threads.emplace_back(send_pings, sock, identifier);
    }
    
    // Aguarda o término das threads de envio
    for (auto& t : sender_threads) {
        t.join();
    }
    
    std::cout << "Envio concluído. Aguardando respostas finais..." << std::endl;
    
    // Aguarda um pouco para receber respostas finais
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Sinaliza para as outras threads pararem
    should_stop = true;
    queue_cv.notify_all();
    
    // Aguarda o término das threads
    receiver_thread.join();
    processor_thread.join();
    stats_thread_obj.join();
    
    // Exibe estatísticas finais
    std::cout << "\n=== Resultados Finais ===\n";
    std::cout << "Total de pacotes enviados: " << sent_count.load() << std::endl;
    std::cout << "Total de respostas recebidas: " << received_count.load() << std::endl;
    std::cout << "Taxa de sucesso: " 
              << (sent_count.load() > 0 ? (received_count.load() * 100.0 / sent_count.load()) : 0.0)
              << "%" << std::endl;
    
    // Fecha o socket
    close(sock);
    return 0;
}

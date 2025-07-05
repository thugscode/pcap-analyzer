#include <iostream>
#include <string>
#include <vector>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <crow.h>
#include <nlohmann/json.hpp>
#include <ctime>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <fstream>
#include <unistd.h>
#include <limits.h>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <regex>
#include <netdb.h>
#include <cstring>
#include <filesystem>

// For convenience
using json = nlohmann::json;

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Enhanced packet information structure
struct PacketInfo {
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    std::string src_mac;
    std::string dst_mac;
    std::string protocol;
    int length;
    
    // Network layer info
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    int ttl = 0;
    
    // TCP specific
    bool syn_flag = false;
    bool ack_flag = false;
    bool fin_flag = false;
    bool rst_flag = false;
    std::string tcp_flags;
    int seq_num = 0;
    int ack_num = 0;
    
    // ICMP specific
    int icmp_type = -1;
    int icmp_code = -1;
    
    // DNS info
    std::vector<std::string> dns_queries;
    
    // HTTP info
    std::string http_method;
    std::string http_uri;
    std::string http_host;
    std::string http_user_agent;
    
    // ARP info
    bool is_arp = false;
    bool potential_arp_spoofing = false;
    
    // TLS info
    bool is_tls = false;
    std::string tls_sni;
    
    // File transfer indicators
    bool potential_file_transfer = false;
    std::string file_transfer_info;
    
    // Credentials detection
    bool potential_credentials = false;
    std::string credential_info;
    
    // Timing info
    double delta_time = 0.0;  // Time since previous packet
    
    // Geolocation (to be filled after parsing)
    std::string src_ip_geo;
    std::string dst_ip_geo;
};

// Function declarations
std::vector<PacketInfo> parse_pcap_file(const std::string& filename);
std::string get_protocol_name(u_char protocol_id);
bool file_exists(const std::string& path);
crow::response process_pcap_file(const std::string& filename);
std::string mac_to_string(const unsigned char* mac);
void extract_dns_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len);
void extract_http_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len);
void extract_tls_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len);
void check_for_credentials(PacketInfo& packet_info, const u_char* payload, size_t payload_len);
void check_for_file_transfer(PacketInfo& packet_info, const u_char* payload, size_t payload_len);
std::string get_geolocation(const std::string& ip);

int main() {
    // Use absolute path for PCAP file
    std::string base_dir = "/home/shailesh/Cryptography/pcap-analyzer/backend/";
    std::string pcap_file = base_dir + "input/input.pcap";
    std::string fallback_file = base_dir + "input/input1.pcap";
    
    // Check if file exists
    if (!file_exists(pcap_file)) {
        std::cerr << "Warning: Cannot access " << pcap_file << std::endl;
    }
    
    // Create Crow application
    crow::SimpleApp app;

    // CORS middleware is not available in Crow by default.
    // CORS headers will be added manually to responses in each route as needed.

    // Define route for packet data
    CROW_ROUTE(app, "/api/packets")
    ([pcap_file, fallback_file]() {
        try {
            auto response = process_pcap_file(pcap_file);
            response.add_header("Access-Control-Allow-Origin", "*");
            response.set_header("Content-Type", "application/json");
            return response;
        } catch (const std::exception& e) {
            try {
                auto response = process_pcap_file(fallback_file);
                response.add_header("Access-Control-Allow-Origin", "*");
                response.set_header("Content-Type", "application/json");
                return response;
            } catch (const std::exception& e2) {
                auto response = crow::response(500, "Error: Could not process PCAP files");
                response.add_header("Access-Control-Allow-Origin", "*");
                return response;
            }
        }
    });

    // Add OPTIONS handler for preflight requests
    CROW_ROUTE(app, "/api/packets")
    .methods("OPTIONS"_method)
    ([](const crow::request& req) {
        crow::response res;
        res.add_header("Access-Control-Allow-Origin", "*");
        res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        res.code = 204; // No content for OPTIONS response
        return res;
    });

    // Add status endpoint
    CROW_ROUTE(app, "/status")
    ([]() {
        return crow::response(200, "Server is running");
    });

    // Define upload route for PCAP files
    CROW_ROUTE(app, "/api/upload")
        .methods("POST"_method)
        ([base_dir](const crow::request& req) {
            try {
                // Get the multipart/form-data content
                auto& body = req.body;
                
                // Check if there's a file in the request
                if (req.headers.count("Content-Type") == 0 ||
                    req.headers.find("Content-Type")->second.find("multipart/form-data") == std::string::npos) {
                    return crow::response(400, "Bad request: Expected multipart/form-data");
                }
                
                // Extract boundary from Content-Type header
                std::string content_type = req.headers.find("Content-Type")->second;
                size_t boundary_pos = content_type.find("boundary=");
                if (boundary_pos == std::string::npos) {
                    return crow::response(400, "Bad request: No boundary found");
                }
                
                std::string boundary = "--" + content_type.substr(boundary_pos + 9);
                
                // Find the file data in the multipart body
                size_t pos = body.find("filename=");
                if (pos == std::string::npos) {
                    return crow::response(400, "Bad request: No filename found");
                }
                
                // Extract filename (optional, you can use a fixed name)
                size_t filename_start = body.find("\"", pos) + 1;
                size_t filename_end = body.find("\"", filename_start);
                std::string filename = body.substr(filename_start, filename_end - filename_start);
                
                // Find the content after the headers
                size_t content_pos = body.find("\r\n\r\n", pos);
                if (content_pos == std::string::npos) {
                    return crow::response(400, "Bad request: Invalid multipart format");
                }
                content_pos += 4;
                
                // Find the end boundary
                size_t content_end = body.find(boundary, content_pos);
                if (content_end == std::string::npos) {
                    return crow::response(400, "Bad request: No end boundary found");
                }
                content_end -= 2; // Remove \r\n before the boundary
                
                // Extract the file content
                std::string file_content = body.substr(content_pos, content_end - content_pos);
                
                // Create input directory if it doesn't exist
                std::string input_dir = base_dir + "input/";
                std::filesystem::create_directories(input_dir);
                
                // Save file as input.pcap
                std::ofstream outfile(input_dir + "input.pcap", std::ios::binary);
                if (!outfile) {
                    return crow::response(500, "Server error: Could not create file");
                }
                
                outfile.write(file_content.c_str(), file_content.size());
                outfile.close();
                
                // Return success response
                json response = {
                    {"success", true},
                    {"message", "File uploaded successfully"},
                    {"filename", "input.pcap"},
                    {"size", file_content.size()}
                };
                
                return crow::response(200, response.dump(4));
            } catch (const std::exception& e) {
                return crow::response(500, std::string("Server error: ") + e.what());
            }
        });

    // API root info
    CROW_ROUTE(app, "/api")
    ([]() {
        json api_info = {
            {"name", "PCAP Analyzer API"},
            {"version", "1.0.0"},
            {"endpoints", {
                {
                    {"path", "/api/packets"},
                    {"method", "GET"},
                    {"description", "Get packet data from the analyzed PCAP file"}
                },
                {
                    {"path", "/api/upload"},
                    {"method", "POST"},
                    {"description", "Upload a new PCAP file for analysis"}
                },
                {
                    {"path", "/status"},
                    {"method", "GET"},
                    {"description", "Check server status"}
                }
            }}
        };
        
        return crow::response(api_info.dump(4));
    });

    // Serve static files for frontend
    CROW_ROUTE(app, "/<path>")
    ([](const crow::request& req, std::string path) {
        std::string static_dir = "/home/shailesh/Cryptography/pcap-analyzer/frontend/";
        std::string file_path = static_dir + path;
        
        // Default to index.html for root path
        if (path.empty()) {
            file_path = static_dir + "index.html";
        }
        
        std::ifstream file(file_path.c_str(), std::ios::in);
        if(file) {
            std::ostringstream contents;
            contents << file.rdbuf();
            file.close();
            
            // Helper lambda for ends_with (C++17 compatible)
            auto ends_with = [](const std::string& value, const std::string& ending) {
                if (ending.size() > value.size()) return false;
                return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
            };

            // Set content type based on file extension
            std::string content_type = "text/plain";
            if (ends_with(path, ".html")) content_type = "text/html";
            else if (ends_with(path, ".css")) content_type = "text/css";
            else if (ends_with(path, ".js")) content_type = "application/javascript";
            else if (ends_with(path, ".json")) content_type = "application/json";
            else if (ends_with(path, ".png")) content_type = "image/png";
            else if (ends_with(path, ".jpg") || ends_with(path, ".jpeg")) content_type = "image/jpeg";
            else if (ends_with(path, ".svg")) content_type = "image/svg+xml";
            
            crow::response res(contents.str());
            res.set_header("Content-Type", content_type);
            return res;
        }
        
        return crow::response(404, "File not found");
    });
    
    // Special case for the root path to serve index.html
    CROW_ROUTE(app, "/")
    ([]() {
        std::string index_path = "/home/shailesh/Cryptography/pcap-analyzer/frontend/index.html";
        std::ifstream file(index_path.c_str(), std::ios::in);
        if(file) {
            std::ostringstream contents;
            contents << file.rdbuf();
            file.close();
            
            crow::response res(contents.str());
            res.set_header("Content-Type", "text/html");
            return res;
        }
        
        return crow::response(404, "Frontend not found. Please build the frontend and place it in the /frontend directory.");
    });

    // Run the server
    app.port(18080).multithreaded().run();
    return 0;
}

// Process PCAP file and return response
crow::response process_pcap_file(const std::string& filename) {
    auto packets = parse_pcap_file(filename);
    
    json response = json::array();
    for (const auto& packet : packets) {
        json packet_json = {
            {"timestamp", packet.timestamp},
            {"src_ip", packet.src_ip},
            {"dst_ip", packet.dst_ip},
            {"src_mac", packet.src_mac},
            {"dst_mac", packet.dst_mac},
            {"protocol", packet.protocol},
            {"length", packet.length},
            {"ttl", packet.ttl}
        };
        
        // Add protocol-specific information
        if (packet.protocol == "TCP") {
            packet_json["src_port"] = packet.src_port;
            packet_json["dst_port"] = packet.dst_port;
            packet_json["syn"] = packet.syn_flag;
            packet_json["ack"] = packet.ack_flag;
            packet_json["fin"] = packet.fin_flag;
            packet_json["rst"] = packet.rst_flag;
            packet_json["tcp_flags"] = packet.tcp_flags;
            packet_json["seq_num"] = packet.seq_num;
            packet_json["ack_num"] = packet.ack_num;
        } 
        else if (packet.protocol == "UDP") {
            packet_json["src_port"] = packet.src_port;
            packet_json["dst_port"] = packet.dst_port;
        } 
        else if (packet.protocol == "ICMP") {
            packet_json["type"] = packet.icmp_type;
            packet_json["code"] = packet.icmp_code;
        }
        else if (packet.is_arp) {
            packet_json["is_arp"] = true;
            packet_json["potential_arp_spoofing"] = packet.potential_arp_spoofing;
        }
        
        // Add DNS information if available
        if (!packet.dns_queries.empty()) {
            packet_json["dns_queries"] = packet.dns_queries;
        }
        
        // Add HTTP information if available
        if (!packet.http_method.empty()) {
            packet_json["http_method"] = packet.http_method;
            packet_json["http_uri"] = packet.http_uri;
            packet_json["http_host"] = packet.http_host;
            packet_json["http_user_agent"] = packet.http_user_agent;
        }
        
        // Add TLS information if available
        if (packet.is_tls) {
            packet_json["is_tls"] = true;
            packet_json["tls_sni"] = packet.tls_sni;
        }
        
        // Add credential detection
        if (packet.potential_credentials) {
            packet_json["potential_credentials"] = true;
            packet_json["credential_info"] = packet.credential_info;
        }
        
        // Add file transfer detection
        if (packet.potential_file_transfer) {
            packet_json["potential_file_transfer"] = true;
            packet_json["file_transfer_info"] = packet.file_transfer_info;
        }
        
        // Add geolocation info
        if (!packet.src_ip_geo.empty()) {
            packet_json["src_ip_geo"] = packet.src_ip_geo;
        }
        if (!packet.dst_ip_geo.empty()) {
            packet_json["dst_ip_geo"] = packet.dst_ip_geo;
        }
        
        packet_json["delta_time"] = packet.delta_time;
        
        response.push_back(packet_json);
    }
    
    return crow::response{response.dump(4)};
}

// Check if file exists
bool file_exists(const std::string& path) {
    std::ifstream file(path);
    return file.good();
}

// Convert MAC address to string
std::string mac_to_string(const unsigned char* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// Parse PCAP file
std::vector<PacketInfo> parse_pcap_file(const std::string& filename) {
    std::vector<PacketInfo> packets;
    packets.reserve(100);
    
    // ARP cache to detect spoofing
    std::unordered_map<std::string, std::string> arp_cache; // IP -> MAC
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open the PCAP file
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle(
        pcap_open_offline(filename.c_str(), errbuf), 
        pcap_close
    );
    
    if (!handle) {
        throw std::runtime_error(std::string("Could not open PCAP file: ") + errbuf);
    }
    
    // Process packets
    struct pcap_pkthdr header;
    const u_char* packet;
    struct timeval last_ts = {0, 0};
    
    while ((packet = pcap_next(handle.get(), &header)) != nullptr) {
        try {
            PacketInfo packet_info;
            
            // Calculate delta time if not first packet
            if (last_ts.tv_sec != 0 || last_ts.tv_usec != 0) {
                packet_info.delta_time = 
                    (header.ts.tv_sec - last_ts.tv_sec) + 
                    (header.ts.tv_usec - last_ts.tv_usec) / 1000000.0;
            }
            last_ts = header.ts;
            
            // Extract timestamp
            char timestamp_buffer[64];
            struct tm* timeinfo = localtime(&header.ts.tv_sec);
            strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
            packet_info.timestamp = timestamp_buffer;
            
            // Extract packet length
            packet_info.length = header.len;
            
            // Extract Ethernet header
            const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
            
            // Get MAC addresses
            packet_info.src_mac = mac_to_string(eth_header->ether_shost);
            packet_info.dst_mac = mac_to_string(eth_header->ether_dhost);
            
            // Check ARP packets
            if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
                packet_info.is_arp = true;
                packet_info.protocol = "ARP";
                
                // Process ARP packet
                const struct ether_arp* arp_packet = reinterpret_cast<const struct ether_arp*>(packet + sizeof(struct ether_header));
                
                // Extract IP and MAC from ARP packet
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp_packet->arp_spa, src_ip, INET_ADDRSTRLEN);
                packet_info.src_ip = src_ip;
                
                char dst_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp_packet->arp_tpa, dst_ip, INET_ADDRSTRLEN);
                packet_info.dst_ip = dst_ip;
                
                // Check for ARP spoofing
                std::string sender_ip = src_ip;
                std::string sender_mac = mac_to_string(arp_packet->arp_sha);
                
                if (arp_cache.find(sender_ip) != arp_cache.end()) {
                    if (arp_cache[sender_ip] != sender_mac) {
                        packet_info.potential_arp_spoofing = true;
                    }
                }
                
                arp_cache[sender_ip] = sender_mac;
                
                packets.push_back(std::move(packet_info));
                continue;
            }
            
            // Skip non-IP packets after this point
            if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
                continue;
            }
            
            // Extract IP information
            const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
            
            // Get TTL
            packet_info.ttl = ip_header->ip_ttl;
            
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            
            inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
            
            packet_info.src_ip = src_ip;
            packet_info.dst_ip = dst_ip;
            packet_info.protocol = get_protocol_name(ip_header->ip_p);
            
            // Add geolocation information (simplified - in a real app you'd use a GeoIP database)
            packet_info.src_ip_geo = get_geolocation(src_ip);
            packet_info.dst_ip_geo = get_geolocation(dst_ip);
            
            // Get IP header length
            int ip_header_len = ip_header->ip_hl * 4;
            
            // Extract protocol-specific information
            switch(ip_header->ip_p) {
                case IPPROTO_TCP: {
                    const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(
                        reinterpret_cast<const u_char*>(ip_header) + ip_header_len
                    );
                    
                    packet_info.src_port = ntohs(tcp_header->th_sport);
                    packet_info.dst_port = ntohs(tcp_header->th_dport);
                    
                    // Extract TCP flags
                    packet_info.syn_flag = tcp_header->th_flags & TH_SYN;
                    packet_info.ack_flag = tcp_header->th_flags & TH_ACK;
                    packet_info.fin_flag = tcp_header->th_flags & TH_FIN;
                    packet_info.rst_flag = tcp_header->th_flags & TH_RST;
                    
                    // Create a human-readable flag string
                    std::string flags = "";
                    if (tcp_header->th_flags & TH_SYN) flags += "SYN ";
                    if (tcp_header->th_flags & TH_ACK) flags += "ACK ";
                    if (tcp_header->th_flags & TH_FIN) flags += "FIN ";
                    if (tcp_header->th_flags & TH_RST) flags += "RST ";
                    if (tcp_header->th_flags & TH_PUSH) flags += "PSH ";
                    if (tcp_header->th_flags & TH_URG) flags += "URG ";
                    
                    packet_info.tcp_flags = flags;
                    
                    // Extract sequence and acknowledgement numbers
                    packet_info.seq_num = ntohl(tcp_header->th_seq);
                    packet_info.ack_num = ntohl(tcp_header->th_ack);
                    
                    // Extract application layer data
                    int tcp_header_len = tcp_header->th_off * 4;
                    const u_char* payload = reinterpret_cast<const u_char*>(tcp_header) + tcp_header_len;
                    size_t payload_len = ntohs(ip_header->ip_len) - ip_header_len - tcp_header_len;
                    
                    if (payload_len > 0) {
                        // Check for HTTP
                        if (packet_info.src_port == 80 || packet_info.dst_port == 80 || 
                            packet_info.src_port == 8080 || packet_info.dst_port == 8080) {
                            extract_http_info(packet_info, payload, payload_len);
                        }
                        
                        // Check for TLS (HTTPS)
                        if (packet_info.src_port == 443 || packet_info.dst_port == 443) {
                            extract_tls_info(packet_info, payload, payload_len);
                        }
                        
                        // Check for DNS over TCP
                        if (packet_info.src_port == 53 || packet_info.dst_port == 53) {
                            extract_dns_info(packet_info, payload, payload_len);
                        }
                        
                        // Check for potential credentials
                        if (packet_info.src_port == 21 || packet_info.dst_port == 21 ||  // FTP
                            packet_info.src_port == 23 || packet_info.dst_port == 23 ||  // Telnet
                            packet_info.src_port == 80 || packet_info.dst_port == 80) {  // HTTP
                            check_for_credentials(packet_info, payload, payload_len);
                        }
                        
                        // Check for file transfers
                        check_for_file_transfer(packet_info, payload, payload_len);
                    }
                    break;
                }
                
                case IPPROTO_UDP: {
                    const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(
                        reinterpret_cast<const u_char*>(ip_header) + ip_header_len
                    );
                    
                    packet_info.src_port = ntohs(udp_header->uh_sport);
                    packet_info.dst_port = ntohs(udp_header->uh_dport);
                    
                    // Extract DNS info from UDP
                    if (packet_info.src_port == 53 || packet_info.dst_port == 53) {
                        const u_char* payload = reinterpret_cast<const u_char*>(udp_header) + sizeof(struct udphdr);
                        size_t payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
                        extract_dns_info(packet_info, payload, payload_len);
                    }
                    break;
                }
                
                case IPPROTO_ICMP: {
                    const struct icmp* icmp_header = reinterpret_cast<const struct icmp*>(
                        reinterpret_cast<const u_char*>(ip_header) + ip_header_len
                    );
                    
                    packet_info.icmp_type = icmp_header->icmp_type;
                    packet_info.icmp_code = icmp_header->icmp_code;
                    break;
                }
            }
            
            packets.push_back(std::move(packet_info));
        } catch (const std::exception&) {
            // Skip problematic packets
        }
    }
    
    return packets;
}

// Extract DNS query information
void extract_dns_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len) {
    if (payload_len < sizeof(dns_header)) {
        return;
    }
    
    const dns_header* dns = reinterpret_cast<const dns_header*>(payload);
    
    // Skip to the first query
    const u_char* query_ptr = payload + sizeof(dns_header);
    
    // Extract domain name queries
    for (int i = 0; i < ntohs(dns->qdcount) && query_ptr < payload + payload_len; i++) {
        std::string domain;
        
        while (query_ptr < payload + payload_len) {
            uint8_t len = *query_ptr++;
            
            if (len == 0) break;  // End of domain name
            
            if (!domain.empty()) domain += ".";
            
            // Sanity check to prevent buffer overruns
            if (query_ptr + len > payload + payload_len) break;
            
            domain.append(reinterpret_cast<const char*>(query_ptr), len);
            query_ptr += len;
        }
        
        if (!domain.empty()) {
            packet_info.dns_queries.push_back(domain);
        }
        
        // Skip qtype and qclass fields (4 bytes)
        query_ptr += 4;
    }
}

// Extract HTTP information
void extract_http_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len) {
    // Simple HTTP detection - look for common HTTP methods
    std::string payload_str(reinterpret_cast<const char*>(payload), 
                           std::min(payload_len, static_cast<size_t>(1024)));  // Limit to 1KB for performance
    
    // HTTP request methods detection
    std::regex method_regex("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT) ([^ ]+) HTTP");
    std::smatch method_match;
    if (std::regex_search(payload_str, method_match, method_regex) && method_match.size() > 2) {
        packet_info.http_method = method_match[1];
        packet_info.http_uri = method_match[2];
    }
    
    // Extract Host header
    std::regex host_regex("Host: ([^\r\n]+)");
    std::smatch host_match;
    if (std::regex_search(payload_str, host_match, host_regex) && host_match.size() > 1) {
        packet_info.http_host = host_match[1];
    }
    
    // Extract User-Agent header
    std::regex ua_regex("User-Agent: ([^\r\n]+)");
    std::smatch ua_match;
    if (std::regex_search(payload_str, ua_match, ua_regex) && ua_match.size() > 1) {
        packet_info.http_user_agent = ua_match[1];
    }
}

// Extract TLS information (SNI)
void extract_tls_info(PacketInfo& packet_info, const u_char* payload, size_t payload_len) {
    // Minimum size for a ClientHello message with SNI
    if (payload_len < 50) return;
    
    // Check if it's a TLS handshake (content type = 22)
    if (payload[0] != 22) return;
    
    packet_info.is_tls = true;
    
    // Check if it's a ClientHello message (handshake type = 1)
    if (payload[5] != 1) return;
    
    // Simplified SNI extraction (real implementation would be more robust)
    // This is a very basic implementation and will miss many cases
    std::string payload_str(reinterpret_cast<const char*>(payload), payload_len);
    
    // Look for the SNI extension pattern
    size_t sni_pos = payload_str.find("\x00\x00", 50); // Find a possible SNI position
    if (sni_pos != std::string::npos && sni_pos + 7 < payload_len) {
        uint16_t len = ((payload[sni_pos+7] & 0xFF) << 8) | (payload[sni_pos+8] & 0xFF);
        if (sni_pos + 9 + len <= payload_len) {
            // Attempt to extract SNI (very basic, not robust)
            std::string sni(reinterpret_cast<const char*>(payload + sni_pos + 9), len);
            packet_info.tls_sni = sni;
        }
    }
}

// Get protocol name
std::string get_protocol_name(u_char protocol_id) {
    static const std::unordered_map<u_char, std::string> protocol_map = {
        {IPPROTO_TCP, "TCP"},
        {IPPROTO_UDP, "UDP"},
        {IPPROTO_ICMP, "ICMP"},
        {IPPROTO_IP, "IP"},
        {IPPROTO_IGMP, "IGMP"},
        {IPPROTO_GRE, "GRE"},
        {IPPROTO_IPV6, "IPv6"},
        {IPPROTO_ESP, "ESP"},
        {IPPROTO_AH, "AH"},
        {IPPROTO_SCTP, "SCTP"}
    };
    
    auto it = protocol_map.find(protocol_id);
    if (it != protocol_map.end()) {
        return it->second;
    }
    
    return "Other (" + std::to_string(protocol_id) + ")";
}

// Simple geolocation function - in a real app you'd use a GeoIP database
std::string get_geolocation(const std::string& ip) {
    // This is a stub implementation - in production you would use a GeoIP database
    // For now, we'll just use a simple heuristic for demonstration
    
    // Check for local/private IP addresses
    if (ip.substr(0, 3) == "10." || 
        ip.substr(0, 8) == "192.168." || 
        ip == "127.0.0.1" || 
        (ip.substr(0, 4) == "172." && 
         std::stoi(ip.substr(4, ip.find('.', 4) - 4)) >= 16 && 
         std::stoi(ip.substr(4, ip.find('.', 4) - 4)) <= 31)) {
        return "Local Network";
    }
    
    // For educational purposes only - this is not accurate geolocation
    // In a real application, use a proper GeoIP database
    if (ip.substr(0, 3) == "8.8") return "United States"; // Google DNS
    if (ip.substr(0, 7) == "157.240") return "United States"; // Facebook
    if (ip.substr(0, 6) == "13.107") return "United States"; // Microsoft
    if (ip.substr(0, 5) == "104.") return "United States"; // Cloudflare
    if (ip.substr(0, 5) == "205.") return "Canada";
    if (ip.substr(0, 5) == "103.") return "Asia/Pacific";
    if (ip.substr(0, 5) == "193.") return "Europe";
    
    return "Unknown"; // Default for IPs we don't recognize
}

// Check for potential credentials in packet payload
void check_for_credentials(PacketInfo& packet_info, const u_char* payload, size_t payload_len) {
    // Convert payload to string for easier regex matching
    std::string payload_str(reinterpret_cast<const char*>(payload), 
                           std::min(payload_len, static_cast<size_t>(2048)));
    
    // Check for common authentication patterns
    
    // HTTP Basic Auth
    std::regex basic_auth_regex("Authorization:\\s*Basic\\s+([A-Za-z0-9+/=]+)");
    std::smatch basic_auth_match;
    if (std::regex_search(payload_str, basic_auth_match, basic_auth_regex)) {
        packet_info.potential_credentials = true;
        packet_info.credential_info = "HTTP Basic Auth detected";
        return;
    }
    
    // Login forms
    std::regex login_regex("(?:username|user|login|email|mail)\\s*[=:]\\s*([^&\\s]+)", 
                         std::regex::icase);
    std::regex password_regex("(?:password|passwd|pwd)\\s*[=:]\\s*([^&\\s]+)",
                            std::regex::icase);
    
    std::smatch login_match, password_match;
    bool has_login = std::regex_search(payload_str, login_match, login_regex);
    bool has_password = std::regex_search(payload_str, password_match, password_regex);
    
    if (has_login && has_password) {
        packet_info.potential_credentials = true;
        packet_info.credential_info = "Potential login form detected";
        return;
    }
    
    // FTP authentication
    std::regex ftp_user_regex("USER\\s+([^\r\n]+)", std::regex::icase);
    std::regex ftp_pass_regex("PASS\\s+([^\r\n]+)", std::regex::icase);
    
    if (std::regex_search(payload_str, ftp_user_regex) || 
        std::regex_search(payload_str, ftp_pass_regex)) {
        packet_info.potential_credentials = true;
        packet_info.credential_info = "FTP authentication detected";
        return;
    }
}

// Check for potential file transfers
void check_for_file_transfer(PacketInfo& packet_info, const u_char* payload, size_t payload_len) {
    // Convert a portion of payload to string for regex matching
    std::string payload_str(reinterpret_cast<const char*>(payload), 
                           std::min(payload_len, static_cast<size_t>(1024)));
    
    // Check for HTTP file download indicators
    std::regex content_disposition_regex(
        "Content-Disposition:\\s*attachment;\\s*filename=[\"']?([^\"'\\r\\n;]+)",
        std::regex::icase
    );
    std::smatch content_match;
    
    if (std::regex_search(payload_str, content_match, content_disposition_regex) && 
        content_match.size() > 1) {
        packet_info.potential_file_transfer = true;
        packet_info.file_transfer_info = "HTTP download: " + content_match[1].str();
        return;
    }
    
    // Check for FTP file operations
    std::regex ftp_get_regex("RETR\\s+([^\r\n]+)", std::regex::icase);
    std::regex ftp_put_regex("STOR\\s+([^\r\n]+)", std::regex::icase);
    
    std::smatch ftp_get_match, ftp_put_match;
    if (std::regex_search(payload_str, ftp_get_match, ftp_get_regex) && 
        ftp_get_match.size() > 1) {
        packet_info.potential_file_transfer = true;
        packet_info.file_transfer_info = "FTP download: " + ftp_get_match[1].str();
        return;
    }
    
    if (std::regex_search(payload_str, ftp_put_match, ftp_put_regex) && 
        ftp_put_match.size() > 1) {
        packet_info.potential_file_transfer = true;
        packet_info.file_transfer_info = "FTP upload: " + ftp_put_match[1].str();
        return;
    }
    
    // Check for common file extensions in URLs
    std::regex url_file_regex(
        "GET\\s+\\S*?([\\w\\-]+\\.(zip|exe|pdf|doc|docx|xls|xlsx|jpg|png|gif|mp3|mp4|avi|mov))\\s+HTTP",
        std::regex::icase
    );
    
    std::smatch url_match;
    if (std::regex_search(payload_str, url_match, url_file_regex) && 
        url_match.size() > 1) {
        packet_info.potential_file_transfer = true;
        packet_info.file_transfer_info = "HTTP file request: " + url_match[1].str();
        return;
    }
}
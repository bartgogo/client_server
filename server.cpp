#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <vector>
#include <fstream>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Base64解码
std::string base64_decode(const std::string& input) {
    BIO *bio, *b64;
    char *buffer = (char *)malloc(input.size());
    memset(buffer, 0, input.size());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_size = BIO_read(bio, buffer, input.size());
    std::string output(buffer, decoded_size);
    free(buffer);
    BIO_free_all(bio);
    return output;
}

// 计算CRC32校验码
uint32_t calculate_crc32(const std::string& data) {
    return crc32(0L, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
}

void store_data(const std::string& data) {
    sqlite3 *db;
    sqlite3_open("data.db", &db);

    std::string sql = "CREATE TABLE IF NOT EXISTS Data (ID INTEGER PRIMARY KEY AUTOINCREMENT, Content TEXT);";
    sqlite3_exec(db, sql.c_str(), 0, 0, 0);

    sql = "INSERT INTO Data (Content) VALUES (?);";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, data.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void session(int client_sock) {
    try {
        while (true) {
            char data_type;
            if (recv(client_sock, &data_type, 1, 0) <= 0) break;

            uint32_t received_crc32;
            if (recv(client_sock, &received_crc32, sizeof(received_crc32), 0) <= 0) break;

            // 如果是文件，接收文件名
            std::string filename;
            if (data_type == 'F') {
                uint16_t filename_len;
                if (recv(client_sock, reinterpret_cast<char*>(&filename_len), sizeof(filename_len), 0) <= 0) break;

                std::vector<char> filename_buffer(filename_len);
                if (recv(client_sock, filename_buffer.data(), filename_len, 0) <= 0) break;
                filename = std::string(filename_buffer.begin(), filename_buffer.end());
            }

            // 接收数据长度
            uint32_t data_len;
            if (recv(client_sock, reinterpret_cast<char*>(&data_len), sizeof(data_len), 0) <= 0) break;

            // 调整缓冲区大小接收数据
            std::vector<char> data_buffer(data_len);
            ssize_t received = 0;
            while (received < data_len) {
                ssize_t length = recv(client_sock, data_buffer.data() + received, data_len - received, 0);
                if (length <= 0) break;
                received += length;
            }
            if (received != data_len) break;  // 数据接收不完整则退出

            std::string encoded_data(data_buffer.begin(), data_buffer.end());
            std::string decoded_data = base64_decode(encoded_data);
            uint32_t calculated_crc32 = calculate_crc32(decoded_data);

            if (received_crc32 == calculated_crc32) {
                if (data_type == 'F') {
                    std::ofstream file(filename, std::ios::binary);
                    file.write(decoded_data.c_str(), decoded_data.size());
                } else if (data_type == 'D') {
                    store_data(decoded_data);
                }
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Exception in thread: " << e.what() << "\n";
    }

    close(client_sock);
}

/*
void session(int client_sock) {
    try {
        while (true) {
            char data_type;
            if (recv(client_sock, &data_type, 1, 0) <= 0) break;

            uint32_t received_crc32;
            if (recv(client_sock, &received_crc32, sizeof(received_crc32), 0) <= 0) break;

            // 如果是文件，接收文件名
            std::string filename;
            if (data_type == 'F') {
                uint16_t filename_len;
                if (recv(client_sock, reinterpret_cast<char*>(&filename_len), sizeof(filename_len), 0) <= 0) break;

                char filename_buffer[256];  // Adjust size as needed
                if (recv(client_sock, filename_buffer, filename_len, 0) <= 0) break;
                filename = std::string(filename_buffer, filename_len);
            }

            char data[512];
            ssize_t length = recv(client_sock, data, sizeof(data), 0);
            if (length <= 0) break;

            std::string encoded_data(data, length);
            std::string decoded_data = base64_decode(encoded_data);
            uint32_t calculated_crc32 = calculate_crc32(decoded_data);

            if (received_crc32 == calculated_crc32) {
                if (data_type == 'F') {
                    std::ofstream file(filename, std::ios::binary);
                    file.write(decoded_data.c_str(), decoded_data.size());
                } else if (data_type == 'D') {
                    store_data(decoded_data);
                }
            }
        }
    } catch (std::exception& e) {
        std::cerr << "Exception in thread: " << e.what() << "\n";
    }

    close(client_sock);
}
*/


void server() {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_sock, (sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);

    while (true) {
        int client_sock = accept(server_sock, NULL, NULL);
        std::thread(session, client_sock).detach();
    }

    close(server_sock);
}

int main() {
    server();
    return 0;
}

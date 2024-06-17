#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <queue>
#include <mutex>
#include <condition_variable>

// Base64����
std::string base64_encode(const std::string& input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    std::string output(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return output;
}

// ����CRC32У����
uint32_t calculate_crc32(const std::string& data) {
    return crc32(0L, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
}

// �ڷ���ʵ������֮ǰ���������ݳ���
void send_data(SOCKET& sock, const std::string& data, bool is_file, const std::string& filename = "") {
    std::string encoded_data = base64_encode(data);
    uint32_t crc32_checksum = calculate_crc32(data);

    // �����������ͣ��ֶ����ݻ��ļ���
    char data_type = is_file ? 'F' : 'D';
    send(sock, &data_type, 1, 0);

    // ����CRC32У����
    send(sock, reinterpret_cast<char*>(&crc32_checksum), sizeof(crc32_checksum), 0);

    // ������ļ��������ļ������Ⱥ��ļ���
    if (is_file) {
        uint16_t filename_len = filename.size();
        send(sock, reinterpret_cast<char*>(&filename_len), sizeof(filename_len), 0);
        send(sock, filename.c_str(), filename_len, 0);
    }

    // ����ʵ�����ݳ���
    uint32_t data_len = encoded_data.size();
    send(sock, reinterpret_cast<char*>(&data_len), sizeof(data_len), 0);

    // ����ʵ������
    send(sock, encoded_data.c_str(), encoded_data.size(), 0);
}

// ����ṹ��
struct Task {
    std::string data;
    bool is_file;
    std::string filename;
};

std::queue<Task> task_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
bool done = false;

void client_thread() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "121.37.136.57", &server_addr.sin_addr);

    connect(sock, (sockaddr*)&server_addr, sizeof(server_addr));

    while (true) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cv.wait(lock, []{ return !task_queue.empty() || done; });

        if (done && task_queue.empty()) {
            break;
        }

        Task task = task_queue.front();
        task_queue.pop();
        lock.unlock();

        send_data(sock, task.data, task.is_file, task.filename);
    }

    closesocket(sock);
    WSACleanup();
}

int main() {
    std::thread client(client_thread);

    // �û�����
    while (true) {
        std::string input;
        std::cout << "�������ֶ����ݻ��ļ�·����";
        std::getline(std::cin, input);

        if (input == "exit") {
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                done = true;
            }
            queue_cv.notify_one();
            break;
        }

        Task task;
        std::ifstream file(input, std::ios::binary);
        if (file) {
            // ��ȡ�ļ�����
            size_t pos = input.find_last_of("/\\");
            task.filename = (pos == std::string::npos) ? input : input.substr(pos + 1);

            task.data = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            task.is_file = true;
        } else {
            task.data = input;
            task.is_file = false;
        }

        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            task_queue.push(task);
        }
        queue_cv.notify_one();
    }

    client.join();
    return 0;
}

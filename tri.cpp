#include <iostream>
#include <functional>
#include <vector>
#include <map>
#include <string>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include "i2psam/i2psam.h"
#include "alberthofman.h"
#include "trigande.h"
#include "ChaCha20.h"

class Client {
public:
    bool connected = false;
    std::string server_dest = "";
    std::string my_dest = "";
    std::shared_ptr<SAM::StreamSession> session;
    std::shared_ptr<SAM::I2pSocket> stream;
    
    std::unique_ptr<DiffiHofman> dh;
    mpz_class shared_key;
    
    i2p::crypto::chacha::Chacha20State chacha_state;
    uint32_t message_counter = 0;

    Client() {}

    bool initSession() {
        if (session && !session->isSick()) return true;
        session = std::make_shared<SAM::StreamSession>("TriClientSession", "127.0.0.1", 7656);
        if (session->isSick()) return false;
        my_dest = session->getMyDestination().pub;
        return true;
    }
};

void deriveKey(const mpz_class& shared, uint8_t* key32) {
    std::string s = shared.get_str(16);
    while (s.size() < 64) s = "0" + s;
    for (size_t i = 0; i < 32; ++i) {
        std::string byteString = s.substr(i * 2, 2);
        key32[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    }
}

std::string trim(const std::string& str) {
    auto start = str.begin();
    while (start != str.end() && std::isspace(*start)) start++;
    auto end = str.end();
    do {
        end--;
    } while (end > start && std::isspace(*end));
    return std::string(start, end + 1);
}

std::string trigObfuscate(const std::string& input) {
    std::string output = input;
    double rad = std::fmod(static_cast<double>(input.size() * 37), 360.0);
    mpf_class sin_val = Triangle::sin_deg(rad, 8);
    mpf_class cos_val = Triangle::cos_deg(rad, 8);
    unsigned long long chaos_key = static_cast<unsigned long long>(std::abs(mpf_get_d(sin_val.get_mpf_t()) * 1000000.0)) ^
                                  static_cast<unsigned long long>(std::abs(mpf_get_d(cos_val.get_mpf_t()) * 1000000.0));
    for (size_t i = 0; i < output.size(); ++i) {
        uint8_t mask = static_cast<uint8_t>((chaos_key >> ((i * 3) % 48)) & 0xFF);
        output[i] = static_cast<char>(output[i] ^ mask);
    }
    return output;
}

using CommandsT = std::map<std::string, std::function<bool(Client &client, std::vector<std::string> params)>>;

CommandsT commands = {
    {"/help", [](Client &client, std::vector<std::string> params) {
        std::cout << "================ МЕНЮ ================\n";
        std::cout << "/help               - справка\n";
        std::cout << "/mykey              - показать ваш I2P Destination\n";
        std::cout << "/connect <dest>     - подключиться к серверу\n";
        std::cout << "/msg <текст>        - отправить зашифрованное сообщение\n";
        std::cout << "/exit               - выход\n";
        std::cout << "======================================\n";
        return true;
    }},
    {"/mykey", [](Client &client, std::vector<std::string> params) {
        std::cout << "Инициализация SAM сессии...\n";
        if (!client.initSession()) {
            std::cout << "Ошибка: не удалось связаться с SAM мостом.\n";
            return true;
        }
        std::cout << "\n[ВАШ DESTINATION]:\n" << client.my_dest << "\n\n";
        return true;
    }},
    {"/connect", [](Client &client, std::vector<std::string> params) {
        if (params.empty()) {
            std::cout << "Ошибка: укажите destination сервера!\n";
            return true;
        }
        client.server_dest = params[0];
        
        if (!client.initSession()) {
            std::cerr << "Ошибка: не удалось запустить SAM сессию клиента.\n";
            return false;
        }

        std::cout << "Подключение к I2P точке (ждите построения туннеля)...\n";
        
        std::thread([&client]() {
            auto lookupResult = client.session->namingLookup(client.server_dest);
            if (!lookupResult.isOk) {
                std::cerr << "\n[Ошибка] NamingLookup не удался.\n> " << std::flush;
                return;
            }

            auto result = client.session->connect(lookupResult.value, false);
            if (!result.isOk || !result.value) {
                std::cerr << "\n[Ошибка] Не удалось установить соединение.\n> " << std::flush;
                return;
            }
            
            client.stream = std::move(result.value);
            client.connected = true;

            // 1. Шлем хендшейк
            client.stream->write("HELLO_TRI\n");
            
            // 2. Ждем подтверждение
            std::string ack;
            for (int i = 0; i < 50; ++i) {
                ack = client.stream->read();
                if (!ack.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            ack = trim(ack);

            if (ack != "WELCOME_TRI") {
                std::cerr << "\n[Ошибка] Сервер отклонил рукопожатие (получено: [" << ack << "]).\n> " << std::flush;
                client.connected = false;
                return;
            }

            std::cout << "\nРукопожатие успешно! Получение параметров DH...\n> " << std::flush;

            // 3. Читаем p и g
            std::string p_str, g_str;
            for (int i = 0; i < 50; ++i) {
                p_str = client.stream->read();
                if (!p_str.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            for (int i = 0; i < 50; ++i) {
                g_str = client.stream->read();
                if (!g_str.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            p_str = trim(p_str);
            g_str = trim(g_str);

            if (p_str.empty() || g_str.empty()) {
                std::cerr << "\n[Ошибка] Сервер не передал параметры p и g.\n> " << std::flush;
                return;
            }
            
            mpz_class p(p_str);
            mpz_class g(g_str);
            client.dh = std::make_unique<DiffiHofman>(p, g);

            // 4. Отправляем свой публичный ключ
            mpz_class pubKey = client.dh->getPublicKey(256);
            client.stream->write(pubKey.get_str() + "\n");

            // 5. Читаем публичный ключ сервера
            std::string serverPubKeyStr;
            for (int i = 0; i < 50; ++i) {
                serverPubKeyStr = client.stream->read();
                if (!serverPubKeyStr.empty()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            serverPubKeyStr = trim(serverPubKeyStr);
            
            if (serverPubKeyStr.empty()) {
                std::cerr << "\n[Ошибка] Не удалось получить публичный ключ сервера.\n> " << std::flush;
                return;
            }

            mpz_class serverPubKey(serverPubKeyStr);
            client.shared_key = client.dh->getSharedKey(serverPubKey);

            uint8_t key32[32];
            deriveKey(client.shared_key, key32);
            uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
            i2p::crypto::chacha::Chacha20Init(client.chacha_state, nonce, key32, 0);
            
            std::cout << "Криптографический контур инициализирован! Можно писать сообщения.\n> " << std::flush;

            // Цикл чтения входящих
            while (client.connected && client.stream) {
                std::string msg = client.stream->read();
                if (msg.empty()) break;
                
                std::string deobf = trigObfuscate(trim(msg));
                std::vector<uint8_t> buf(deobf.begin(), deobf.end());
                i2p::crypto::chacha::Chacha20Encrypt(client.chacha_state, buf.data(), buf.size());
                std::string decrypted(buf.begin(), buf.end());

                std::cout << "\n[Входящее]: " << decrypted << "\n> " << std::flush;
            }
        }).detach();

        return true;
    }},
    {"/msg", [](Client &client, std::vector<std::string> params) {
        if (!client.connected || !client.stream) {
            std::cout << "Сначала подключитесь через /connect <dest>\n";
            return true;
        }
        if (params.empty()) return true;

        std::string text = "";
        for (size_t i = 0; i < params.size(); ++i) {
            text += params[i] + (i + 1 < params.size() ? " " : "");
        }

        client.message_counter++;
        i2p::crypto::chacha::Chacha20SetCounter(client.chacha_state, client.message_counter);

        std::vector<uint8_t> buf(text.begin(), text.end());
        i2p::crypto::chacha::Chacha20Encrypt(client.chacha_state, buf.data(), buf.size());
        std::string encrypted(buf.begin(), buf.end());

        std::string finalPayload = trigObfuscate(encrypted);
        client.stream->write(finalPayload + "\n");
        return true;
    }},
    {"/exit", [](Client &client, std::vector<std::string> params) {
        client.connected = false;
        std::cout << "Выход...\n";
        return false;
    }}
};

int main(int argc, char** argv) {
    Client client;

    // Фоновый поток сервера
    std::thread serverThread([&client]() {
        SAM::StreamSession serverSession("TriServerSession", "127.0.0.1", 7656);
        if (serverSession.isSick()) {
            std::cerr << "Не удалось запустить SAM сервер.\n";
            return;
        }
        
        std::cout << "\n[Сервер запущен]. Введите /mykey чтобы узнать свой ключ.\n> " << std::flush;

        while (true) {
            auto result = serverSession.accept(false);
            if (!result.isOk || !result.value) continue;
            
            auto &stream = *result.value;
            
            std::thread([&stream]() {
                std::string handshake;
                for (int i = 0; i < 50; ++i) {
                    handshake = stream.read();
                    if (!handshake.empty()) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                handshake = trim(handshake);
                if (handshake != "HELLO_TRI") return;

                std::cout << "\n[Сервер] Клиент подтвержден. Генерация параметров p и g...\n> " << std::flush;
                mpz_class s_p = DiffiHofman::random_n(2048); // уменьшено до 2048 для скорости теста, можно вернуть 8192
                mpz_class s_g = DiffiHofman::random_n(128);
                DiffiHofman s_dh(s_p, s_g);

                stream.write("WELCOME_TRI\n");
                stream.write(s_p.get_str() + "\n");
                stream.write(s_g.get_str() + "\n");

                std::string clientPubStr;
                for (int i = 0; i < 50; ++i) {
                    clientPubStr = stream.read();
                    if (!clientPubStr.empty()) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                clientPubStr = trim(clientPubStr);
                if (clientPubStr.empty()) return;

                mpz_class clientPub(clientPubStr);
                mpz_class s_pub = s_dh.getPublicKey(256);
                stream.write(s_pub.get_str() + "\n");

                mpz_class shared = s_dh.getSharedKey(clientPub);
                uint8_t key32[32];
                deriveKey(shared, key32);
                uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
                i2p::crypto::chacha::Chacha20State s_state;
                i2p::crypto::chacha::Chacha20Init(s_state, nonce, key32, 0);
                uint32_t s_counter = 0;

                std::cout << "\n[Сервер] Защищенная сессия установлена!\n> " << std::flush;

                while (true) {
                    std::string msg = stream.read();
                    msg = trim(msg);
                    if (msg.empty() || msg == "EXIT") break;

                    std::string deobf = trigObfuscate(msg);
                    std::vector<uint8_t> buf(deobf.begin(), deobf.end());
                    s_counter++;
                    i2p::crypto::chacha::Chacha20SetCounter(s_state, s_counter);
                    i2p::crypto::chacha::Chacha20Encrypt(s_state, buf.data(), buf.size());
                    std::string decrypted(buf.begin(), buf.end());

                    std::cout << "\n[Сервер принял]: " << decrypted << "\n> " << std::flush;
                }
            }).detach();
        }
    });
    serverThread.detach();

    // Главный цикл ввода команд
    std::string inputLine;
    std::cout << "Введите /help для справки.\n> ";
    while (std::getline(std::cin, inputLine)) {
        if (inputLine.empty()) continue;
        
        std::stringstream ss(inputLine);
        std::string cmd;
        ss >> cmd;
        
        std::vector<std::string> params;
        std::string p;
        while (ss >> p) params.push_back(p);

        if (commands.find(cmd) != commands.end()) {
            bool cont = commands[cmd](client, params);
            if (!cont) break;
        } else {
            if (client.connected) {
                std::vector<std::string> msgParams;
                msgParams.push_back(inputLine);
                commands["/msg"](client, msgParams);
            } else {
                std::cout << "Неизвестная команда. Введите /help\n";
            }
        }
        std::cout << "> " << std::flush;
    }

    return 0;
}

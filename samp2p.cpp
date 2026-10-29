#include <memory>
/*
 * P2P SAM chat with DH + ChaCha20 + trigonometric rekey
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <memory>
#if __cplusplus < 201402L
namespace std {
template<typename T, typename... Args>
unique_ptr<T> make_unique(Args&&... args) {
  return unique_ptr<T>(new T(std::forward<Args>(args)...));
}
}
#endif
#include <cstdint>
#include <fstream>
#include <iomanip>

#include <ncurses.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>

#include "i2psam/i2psam.h"
#include "alberthofman.h"
#include "trigande.h"
#include "ChaCha20.h"

using namespace std;
using namespace std::chrono;

static volatile sig_atomic_t g_running = 1;

void sigint_handler(int) {
    g_running = 0;
}

enum class State {
    INIT,
    VERIFY,
    DH_EXCHANGE,
    CHAT
};

struct Msg {
    string type;
    string data;
};

string trim(const string &s) {
    size_t b = s.find_first_not_of(" \r\n\t");
    if (b == string::npos) return "";
    size_t e = s.find_last_not_of(" \r\n\t");
    return s.substr(b, e-b+1);
}

vector<string> split(const string &s, char delim) {
    vector<string> out;
    string cur;
    for(char c : s) {
        if(c == delim) {
            if(!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else {
            cur += c;
        }
    }
    if(!cur.empty()) out.push_back(cur);
    return out;
}

string mpz_to_hex(const mpz_class &x) {
    stringstream ss;
    ss << hex << x;
    string h = ss.str();
    // gmp may give lowercase
    return h;
}

mpz_class hex_to_mpz(const string &h) {
    mpz_class r;
    // mpz_set_str
    mpz_set_str(r.get_mpz_t(), h.c_str(), 16);
    return r;
}

// derive 32 byte key from shared + trig
vector<unsigned char> derive_chacha_key(const mpz_class &shared, unsigned long tick) {
    vector<unsigned char> key(32, 0);
    // mix shared bytes
    string sh = shared.get_str(16);
    for(size_t i = 0; i < 32 && i < sh.size(); i++) {
        key[i] ^= (unsigned char)strtol(sh.substr(i*2,2).c_str(), nullptr, 16);
    }
    // mix with sin/cos
    double ang = fmod((double)tick * 0.01337, 2.0 * M_PI);
    mpf_class s = Triangle::sin_rads(mpf_class(ang), 12, false);
    mpf_class c = Triangle::cos_rads(mpf_class(ang), 12, false);
    mp_exp_t exps=0, expc=0;
    string ss = s.get_str(exps);
    string cs = c.get_str(expc);
    for(size_t i = 0; i < 16 && i < ss.size(); i++) key[i] ^= (unsigned char)(ss[i] * 131542391ULL);
    for(size_t i = 0; i < 16 && i < cs.size(); i++) key[16+i] ^= (unsigned char)(cs[i] * 1000000009ULL);
    // mix tick
    for(int i = 0; i < 32; i++) key[i] ^= (unsigned char)((tick >> (i%8)) & 0xFF);
    return key;
}

vector<unsigned char> derive_nonce(const mpz_class &shared, unsigned long tick) {
    vector<unsigned char> nonce(12, 0);
    string sh = shared.get_str(10);
    for(size_t i = 0; i < 12 && i < sh.size(); i++) nonce[i] ^= (unsigned char)sh[i];
    double ang2 = fmod((double)tick * 0.00713 + 1.618, 2.0 * M_PI);
    mpf_class s = Triangle::sin_rads(mpf_class(ang2), 10, false);
    mp_exp_t exps=0;
    string ss = s.get_str(exps);
    for(size_t i = 0; i < 12 && i < ss.size(); i++) nonce[i] ^= (unsigned char)(ss[i] ^ ((tick>>(i))&0xFF));
    return nonce;
}

class Chat {
public:
    Chat() { m_sock = nullptr; sess = nullptr; }
    string nick;
    string mode; // listen/connect
    string dest;
    string samhost = "127.0.0.1";
    uint16_t samport = 7656;

    void* sess;
    State state = State::INIT;
    mutex mtx;
    I2pSocket* m_sock;

    // dh
    unique_ptr<DiffiHofman> dh;
    mpz_class p,g;
    mpz_class my_pub;
    mpz_class their_pub;
    mpz_class shared;

    // crypto
    atomic<unsigned long> rekey_tick{0};
    time_t last_rekey{0};
    vector<unsigned char> ckey;
    vector<unsigned char> cnonce;
    bool crypto_ready = false;

    // ui
    vector<string> loglines;
    string inputbuf;

    void log(const string &s) {
        lock_guard<mutex> lk(mtx);
        time_t now = time(0);
        char ts[64];
        strftime(ts, sizeof(ts), "[%H:%M:%S]", localtime(&now));
        loglines.push_back(string(ts) + " " + s);
        if(loglines.size() > 200) loglines.erase(loglines.begin());
    }

    bool setup_dh() {
        try {
            // use smaller primes for interactive chat
            p = DiffiHofman::random_n(512);
            g = DiffiHofman::random_n(64);
            dh.reset(new DiffiHofman(p,g));
            my_pub = dh->getPublicKey(256);
            log("DH params generated");
            return true;
        } catch(exception &e) {
            log(string("DH err: ") + e.what());
            return false;
        }
    }

    void do_rekey() {
        if(!crypto_ready) return;
        time_t now = time(0);
        if(now - last_rekey < 300) return;
        rekey_tick++;
        ckey = derive_chacha_key(shared, rekey_tick);
        cnonce = derive_nonce(shared, rekey_tick);
        last_rekey = now;
        log("ChaCha20 key rekeyed (trig+shared)");
    }

    void init_crypto() {
        rekey_tick = 1;
        ckey = derive_chacha_key(shared, rekey_tick);
        cnonce = derive_nonce(shared, rekey_tick);
        last_rekey = time(0);
        crypto_ready = true;
        log("Crypto ready: ChaCha20");
    }

    void encrypt_send(const string &msg) {
        if(!crypto_ready || !sock) return;
        string txt = "[MSG]" + nick + ":" + msg + "\n";
        vector<unsigned char> buf(txt.begin(), txt.end());
        i2p::crypto::chacha::Chacha20State st;
        i2p::crypto::chacha::Chacha20Init(st, cnonce.data(), ckey.data(), 0);
        i2p::crypto::chacha::Chacha20Encrypt(st, buf.data(), buf.size());
        string out(buf.begin(), buf.end());
        m_sock->write(out);
    }

    string decrypt_recv(const string &in) {
        if(!crypto_ready || in.empty()) return in;
        vector<unsigned char> buf(in.begin(), in.end());
        i2p::crypto::chacha::Chacha20State st;
        i2p::crypto::chacha::Chacha20Init(st, cnonce.data(), ckey.data(), 0);
        i2p::crypto::chacha::Chacha20Encrypt(st, buf.data(), buf.size());
        return string(buf.begin(), buf.end());
    }

    void send_line(const string &l) {
        if(!m_sock && !sockp) return;
        m_sock->write(l + "\n");
    }

    string recv_line() {
        if(!m_sock && !sockp) return "";
        string r = m_sock->read();
        if(r.empty()) return "";
        // try to split by \n
        size_t pos = r.find('\n');
        if(pos != string::npos) {
            return r.substr(0,pos);
        }
        return r;
    }

    void run() {
        initscr();
        cbreak();
        noecho();
        keypad(stdscr, TRUE);
        nodelay(stdscr, TRUE);
        curs_set(1);

        int h,w; getmaxyx(stdscr,h,w);
        I2pSocket* sockp = m_sock;

        if(mode == "listen") {
            log("Starting SAM stream session (listen)...");
            try {
                sess = (void*)new SAM::StreamSession(nick, samhost, samport);
                log("Session created. Waiting for incoming connection...");
                { SAM::StreamSession* sss = (SAM::StreamSession*)sess; log("My dest: " + sss->getMyDestination().pub); }
                { SAM::StreamSession* sss = (SAM::StreamSession*)sess; auto res = sss->accept(false);
                if(res.isOk) {
                    { auto xv = res.value.release(); m_sock = static_cast<I2pSocket*>(xv); sockp = m_sock; }
                    log("Incoming connection accepted");
                    state = State::VERIFY;
                } else {
                    log("Accept failed");
                    g_running = 0;
                }
            } catch(exception &e) {
                log(string("err:") + e.what());
                g_running = 0;
            }
        } else if(mode == "connect") {
            log("Starting SAM stream session...");
            try {
                sess = (void*)new SAM::StreamSession(nick, samhost, samport);
                log("Connecting to: " + dest.substr(0,40) + "...");
                { auto s1 = (SAM::StreamSession*)sess; auto lookup = s1->namingLookup(dest);
                  string target = dest;
                  if(lookup.isOk) target = lookup.value;
                  {
                    { SAM::StreamSession* ssr = (SAM::StreamSession*)sess; auto cres = ssr->connect(target, false);
                    if(cres.isOk) {
                        { auto xv = cres.value.release(); m_sock = static_cast<I2pSocket*>(xv); sockp = m_sock; }
                        log("Connected");
                        state = State::VERIFY;
                    } else {
                        log("Connect failed");
                        g_running = 0;
                    }
                  }
                }
            } catch(exception &e) {
                log(string("err:") + e.what());
                g_running = 0;
            }
        }

        time_t last_ping = time(0);
        time_t last_input = time(0);
        while(g_running) {
            // ui
            clear();
            mvprintw(0,0,"SAM P2P CHAT | nick:%s | state:", nick.c_str());
            if(state==State::INIT) printw("INIT");
            else if(state==State::VERIFY) printw("VERIFY");
            else if(state==State::DH_EXCHANGE) printw("DH");
            else if(state==State::CHAT) printw("CHAT (rekey every 5min)");
            mvhline(1,0,'-',w);
            int ly = 2;
            {
                lock_guard<mutex> lk(mtx);
                int start = max(0, (int)loglines.size() - (h-6));
                for(size_t i=start; i<loglines.size() && ly < h-3; i++) {
                    mvprintw(ly++, 0, "%s", loglines[i].c_str());
                }
            }
            mvhline(h-3,0,'-',w);
            mvprintw(h-2,0,"> %s", inputbuf.c_str());
            refresh();

            // periodic
            if(state == State::VERIFY && time(0)-last_ping > 2) {
                send_line("VER:PING");
                last_ping = time(0);
            }
            if(state == State::CHAT) {
                do_rekey();
            }

            // input
            int ch = getch();
            if(ch != ERR) {
                if(ch == KEY_BACKSPACE || ch == 127) {
                    if(!inputbuf.empty()) inputbuf.pop_back();
                } else if(ch == '\n' || ch == KEY_ENTER) {
                    if(!inputbuf.empty()) {
                        if(state == State::CHAT && crypto_ready) {
                            encrypt_send(inputbuf);
                            log(string("[ME] ")+inputbuf);
                        } else if(state == State::VERIFY) {
                            send_line(string("VER:")+inputbuf);
                            log(string("[ME] ")+inputbuf);
                        } else if(state == State::DH_EXCHANGE) {
                            // manual if needed
                            send_line(string("DH:")+inputbuf);
                        } else {
                            send_line(inputbuf);
                        }
                        inputbuf.clear();
                    }
                } else if(ch >= 32 && ch < 127) {
                    if(inputbuf.size() < 200) inputbuf += (char)ch;
                }
            }

            // network
            if(m_sock && m_sock->isOk()) {
                // non-blocking read attempt
                fd_set fds;
                FD_ZERO(&fds);
                // not directly getting fd, but try read with small
                string raw = m_sock->read();
                if(!raw.empty()) {
                    if(state == State::CHAT && crypto_ready) {
                        string dec = decrypt_recv(raw);
                        // split messages
                        stringstream ss(dec);
                        string line;
                        while(getline(ss,line)) {
                            if(line.rfind("[MSG]",0)==0) {
                                size_t p = line.find(':',5);
                                if(p!=string::npos) {
                                    string who = line.substr(5,p-5);
                                    string txt = line.substr(p+1);
                                    log(string("[")+who+"] "+txt);
                                }
                            }
                        }
                    } else {
                        // parse lines
                        stringstream ss(raw);
                        string line;
                        while(getline(ss,line)) {
                            string l = trim(line);
                            if(l.empty()) continue;
                            if(state == State::VERIFY) {
                                if(l == "VER:PONG") {
                                    log("Peer says: PONG - connection verified OK");
                                    // start DH
                                    if(setup_dh()) {
                                        state = State::DH_EXCHANGE;
                                        string m = string("DH:PUB:")+mpz_to_hex(p)+"|"+mpz_to_hex(g)+"|"+mpz_to_hex(my_pub);
                                        send_line(m);
                                        log("Sent DH pub params+key");
                                    }
                                } else if(l.find("VER:") == 0 && l != "VER:PING") {
                                    log(string("Peer:")+l);
                                } else if(l == "VER:PING") {
                                    send_line("VER:PONG");
                                    log("Replied PONG");
                                }
                            } else if(state == State::DH_EXCHANGE) {
                                if(l.find("DH:PUB:") == 0) {
                                    string rest = l.substr(7);
                                    auto v = split(rest,'|');
                                    if(v.size()==3) {
                                        try {
                                            if(p == 0) p = hex_to_mpz(v[0]);
                                            if(g == 0) g = hex_to_mpz(v[1]);
                                            their_pub = hex_to_mpz(v[2]);
                                            if(!dh) {
                                                dh.reset(new DiffiHofman(p,g));
                                            }
                                            shared = dh->getSharedKey(their_pub);
                                            log("Computed shared DH key");
                                            init_crypto();
                                            state = State::CHAT;
                                            log("=== CHAT STARTED (encrypted) ===");
                                            log("Type messages and press ENTER");
                                        } catch(exception &e) {
                                            log(string("DH err:")+e.what());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            this_thread::sleep_for(milliseconds(50));
        }

        { I2pSocket* sp2 = m_sock; if(!sp2 && sockp) sp2 = sockp; if(sp2){sp2->close(); m_sock=nullptr; sockp=nullptr;}}
        if(sess) {
            // sess will cleanup
        }
        endwin();
    }
};

int main(int argc, char **argv) {
    signal(SIGINT, sigint_handler);
    Chat c;
    if(argc < 3) {
        cout << "Usage:" << endl;
        cout << "  " << argv[0] << " --listen --nick <name>" << endl;
        cout << "  " << argv[0] << " --connect <b32.i2p or dest> --nick <name>" << endl;
        return 1;
    }
    for(int i=1;i<argc;i++) {
        string a = argv[i];
        if(a == "--nick" && i+1<argc) c.nick = argv[++i];
        else if(a == "--listen") c.mode = "listen";
        else if(a == "--connect" && i+1<argc) { c.mode = "connect"; c.dest = argv[++i]; }
        else if(a == "--samhost" && i+1<argc) c.samhost = argv[++i];
        else if(a == "--samport" && i+1<argc) c.samport = atoi(argv[++i]);
    }
    if(c.nick.empty()) c.nick = "anon";
    c.run();
    return 0;
}

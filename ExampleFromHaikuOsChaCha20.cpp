#include <iostream>
#include <getopt.h>
#include <filesystem>
#include <fstream>
#include "EncFile.hpp"
#include <Application.h>
#include <Window.h>
#include <View.h>
#include <TextControl.h>
#include <Button.h>
#include <FilePanel.h>
#include <Path.h>
#include <Entry.h>
#include <Roster.h>
#include<Alert.h>
#include <String.h>

//extern int CounterChaCha20; // Предполагается, что это глобальная переменная из EncFile.hpp // predpolagaetsa chto ne trogaj blyat

static struct option long_options[] =
{
    {"key", required_argument, NULL, 'k'},
    {"iv", required_argument, NULL, 'v'},
    {"file", required_argument, NULL, 'f'},
    {"shred", 0, NULL, 's'},
    {"help", 0, NULL, 'h'},
    {"gui", 0, NULL, 'g'},
    {NULL, 0, NULL, 0}
};

void help(void)
{
    std::cout << "Usage program: --key/-k your key password" << std::endl;
    std::cout << "Usage program: --iv/-v your iv" << std::endl;
    std::cout << "Usage program: --file/-f your file" << std::endl;
    std::cout << "Usage program: --init_new/-n (not implemented for a now)" << std::endl;
    std::cout << R"(/a.out --key "Hello World" --iv "123" -f SuperText.txt)" << std::endl;
    std::cout << R"(./a.out --key "Hello World" --iv "123" -f SuperText.txt.enc)" << std::endl;
}
// TODO: TO an another file. gemini pro
// Константы сообщений для кнопок GUI
const uint32 MSG_BTN_SELECT = 'mbsl';
const uint32 MSG_BTN_ENC = 'mbec';
const uint32 MSG_BTN_DEC = 'mbdc';
const uint32 MSG_BTN_SHRED = 'mbsh';
const uint32 MSG_BTN_DIR = 'mbdr';

class MEncryptorWindow : public BWindow {
    BTextControl* fKey;
    BTextControl* fIv;
    BTextControl* fFile;
    BButton* fBtnEnc;
    BButton* fBtnDec;
    BButton* fBtnShred;
    BButton* fBtnDir;
    BFilePanel* fOpenPanel;

public:
    MEncryptorWindow(BRect frame)
    : BWindow(frame, "MEncryptorAPP", B_DOCUMENT_WINDOW_LOOK, B_NORMAL_WINDOW_FEEL, B_NOT_RESIZABLE | B_NOT_ZOOMABLE)
    {
        BView* view = new BView(Bounds(), "mainView", B_FOLLOW_ALL, B_WILL_DRAW);
        view->SetViewColor(ui_color(B_PANEL_BACKGROUND_COLOR));
        AddChild(view);

        // 1. Поле ключа
        fKey = new BTextControl(BRect(10, 10, 340, 35), "key", "Key:", "", NULL);
        fKey->SetDivider(40);

        // 2. Поле IV
        fIv = new BTextControl(BRect(10, 45, 340, 70), "iv", "IV:", "", NULL);
        fIv->SetDivider(40);

        // 3. Поле файла (только для чтения) и кнопка выбора
        fFile = new BTextControl(BRect(10, 80, 290, 105), "file", "File:", "", NULL);
        fFile->SetDivider(40);
        fFile->SetEnabled(false);

        BButton* btnSelect = new BButton(BRect(300, 78, 340, 105), "sel", "...", new BMessage(MSG_BTN_SELECT));

        // 4. Кнопки Encrypt / Decrypt (изначально неактивны до выбора файла)
        fBtnEnc = new BButton(BRect(10, 120, 170, 150), "enc", "Encrypt", new BMessage(MSG_BTN_ENC));
        fBtnDec = new BButton(BRect(180, 120, 340, 150), "dec", "Decrypt", new BMessage(MSG_BTN_DEC));
        fBtnEnc->SetEnabled(false);
        fBtnDec->SetEnabled(false);

        // 5. Кнопки Shred (всегда активна) и Open Folder
        fBtnShred = new BButton(BRect(10, 160, 170, 190), "shred", "Shred", new BMessage(MSG_BTN_SHRED));
        fBtnDir = new BButton(BRect(180, 160, 340, 190), "dir", "Open Folder", new BMessage(MSG_BTN_DIR));

        view->AddChild(fKey);
        view->AddChild(fIv);
        view->AddChild(fFile);
        view->AddChild(btnSelect);
        view->AddChild(fBtnEnc);
        view->AddChild(fBtnDec);
        view->AddChild(fBtnShred);
        view->AddChild(fBtnDir);

        fOpenPanel = new BFilePanel(B_OPEN_PANEL, new BMessenger(this));
    }

    ~MEncryptorWindow() {
        delete fOpenPanel;
    }
    void MessageReceived(BMessage* msg) override {
        switch (msg->what) {
            case MSG_BTN_SELECT: {
                fOpenPanel->Show();
                break;
            }
            case B_REFS_RECEIVED: {
                entry_ref ref;
                if (msg->FindRef("refs", &ref) == B_OK) {
                    BPath path(&ref);
                    BString pathStr(path.Path());
                    fFile->SetText(pathStr.String());

                    // Активация кнопок исходя из ".enc"
                    if (pathStr.EndsWith(".enc")) {
                        fBtnEnc->SetEnabled(false);
                        fBtnDec->SetEnabled(true);
                    } else {
                        fBtnEnc->SetEnabled(true);
                        fBtnDec->SetEnabled(false);
                    }
                }
                break;
            }
            case MSG_BTN_ENC:
            case MSG_BTN_DEC: {
                std::string filepath = fFile->Text();
                std::string key = fKey->Text();
                std::string iv = fIv->Text();

                // Если забыли ввести данные — алерт с предупреждением
                if (filepath.empty() || key.empty() || iv.empty()) {
                    (new BAlert("Error", "you need to write: Key, IV and select the file!",
                                "ОК", NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT))->Go();
                                break;
                }

                CounterChaCha20 = 33;
                bool is_encrypt = (msg->what == MSG_BTN_ENC);

                try {
                    EncFile f{filepath, key, iv, is_encrypt};

                    // ВЫЗОВ BALERT ПРИ УСПЕШНОМ ШИФРОВАНИИ / РАСШИФРОВКЕ
                    if (is_encrypt) {
                        (new BAlert("Success", "File encrypted, look to (.enc) in folder with this file!",
                                    "Nice", NULL, NULL, B_WIDTH_AS_USUAL, B_INFO_ALERT))->Go();
                    } else {
                        (new BAlert("Success", "File decrypted, look to (.dec) in folder with this file!",
                                    "nice", NULL, NULL, B_WIDTH_AS_USUAL, B_INFO_ALERT))->Go();
                    }
                } catch (...) {
                    (new BAlert("Error", "Error!",
                                "ОК", NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT))->Go();
                }
                break;
            }
            case MSG_BTN_SHRED: {
                std::string filepath = fFile->Text();
                if (filepath.empty()) {
                    (new BAlert("Error", "Firstly select the file for shred!",
                                "ОК", NULL, NULL, B_WIDTH_AS_USUAL, B_WARNING_ALERT))->Go();
                                break;
                }
                try {
                    // TODO: to an function constexpr / macros / function / etc/ double code is bad
                    auto size = std::filesystem::file_size(filepath);
                    for (unsigned char i = 33; i--;) {
                        std::ofstream f_out(filepath, std::ios::binary);
                        for (auto s = size; s--;) f_out << i;
                    }
                    // BALERT ПОСЛЕ ШРЕДИНГА
                    (new BAlert("Success", "File shreded!",
                                "Nice", NULL, NULL, B_WIDTH_AS_USUAL, B_INFO_ALERT))->Go();
                } catch(...) {
                    (new BAlert("Error", "Can't to destruct the file!",
                                "ОК", NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT))->Go();
                }
                break;
            }
            case MSG_BTN_DIR: {
                std::string filepath = fFile->Text();
                if (filepath.empty()) {
                    (new BAlert("Error", "For a now select the file!",
                                "ОК", NULL, NULL, B_WIDTH_AS_USUAL, B_WARNING_ALERT))->Go();
                                break;
                }

                BPath path(filepath.c_str());
                BPath parent;
                if (path.GetParent(&parent) == B_OK) {
                    entry_ref dirRef;
                    if (get_ref_for_path(parent.Path(), &dirRef) == B_OK) {
                        be_roster->Launch(&dirRef);
                    }
                }
                break;
            }
            default:
                BWindow::MessageReceived(msg);
                break;
        }
    }

    bool QuitRequested() override {
        be_app->PostMessage(B_QUIT_REQUESTED);
        return true;
    }
};

class MEncryptorApp : public BApplication {
protected:
    MEncryptorWindow* m_window;
public:
    MEncryptorApp(void) : BApplication("application/x-vnd.MENcryptorAPP") {
        m_window = new MEncryptorWindow(BRect(100, 100, 450, 300));
        m_window->Show();
    }
};
int launch_gui(void)
{
    auto app = new MEncryptorApp{};
    app->Run();
    delete app;
    return 0;
}
// TODO ^^ to an another file
int main(int argc, char ** argv, char ** env)
{
    char ch;
    std::string key, iv, filepath;
    bool shred_file = false;

    while ((ch = getopt_long(argc, argv, "gk:v:f:n:hs", long_options, NULL)) != -1)
    {
        switch (ch)
        {
            case 's':
                shred_file = true;
                break;
            case 'g':
                return launch_gui();
                break;
            case 'k':
                key = optarg;
                break;
            case 'v':
                iv = optarg;
                break;
            case 'f':
                filepath = optarg;
                break;
            default:
            case 'h':
                help();
                return 0;
        }
    }

    if (shred_file)
    {
        if(filepath.empty()) {
            std::cerr << "Give a filepath for shred" << std::endl;
            return 1;
        }
        auto size = std::filesystem::file_size(filepath);
        for(unsigned char i=33;i--;)
        {
            std::ofstream f{filepath};
            for(auto s = size;s--;)
            {
                f << i;
            }
        }
        return 0;
    }

    if (filepath.empty() || key.empty() || iv.empty())
    {
        help();
        return 0;
    }

    CounterChaCha20 = 33;

    if (filepath.ends_with(".enc"))
    {
        std::cout << "Decrypt file: " + filepath << std::endl;
        auto f = EncFile{filepath, key, iv, false};
        std::cout << "Check your file in .dec" << std::endl;
    } else
    {
        std::cout << "Encrypt file: " + filepath << std::endl;
        auto f = EncFile{filepath, key, iv, true};
        std::cout << "Check your file in .enc" << std::endl;
    }
    std::cout << "After usage you can want to shred the file" << std::endl;
}


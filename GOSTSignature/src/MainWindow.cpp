#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include "../include/GOSTSigner.h"
#include "../include/StringUtil.h"
#include "../resource.h"

#pragma execution_character_set("utf-8")
#pragma comment(lib, "comctl32.lib")

using namespace gost;

const wchar_t MENU_CLASS_NAME[] = L"GOSTMenuWindow";
const wchar_t SIGN_CLASS_NAME[] = L"GOSTSignatureWindow";
const wchar_t CREATE_USER_CLASS[] = L"GOSTCreateUserWindow";
const wchar_t SELECT_USER_CLASS[] = L"GOSTSelectUserWindow";
const wchar_t KEY_WINDOW_CLASS[] = L"GOSTKeyWindow";

LRESULT CALLBACK MenuWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SignWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK CreateUserWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SelectUserWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK KeyWndProc(HWND, UINT, WPARAM, LPARAM);

void SignOnCreate(HWND hwnd);
void SignOnCommand(HWND hwnd, WPARAM wParam);
void BrowseFile(HWND hwnd);
void UpdateSignature(HWND hwnd);
void SaveSignature(HWND hwnd);
void ShowSettings(HWND hwnd);
void UpdateActiveUserLabel(HWND hwnd);
void RefreshUserList(HWND hwnd, int controlId);
void SyncKeyFields(HWND hwnd);

HWND g_signatureWindow = nullptr;
std::vector<std::wstring> g_users = { L"Администратор" };
std::wstring g_activeUser = L"Не выбран";
std::wstring g_savedPrivateKey;
std::wstring g_savedPublicKey;
HINSTANCE g_hInstance = nullptr;

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    INITCOMMONCONTROLSEX icc{ sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    g_hInstance = hInstance;

    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    wcex.lpfnWndProc = MenuWndProc;
    wcex.lpszClassName = MENU_CLASS_NAME;
    RegisterClassExW(&wcex);

    wcex.lpfnWndProc = SignWndProc;
    wcex.lpszClassName = SIGN_CLASS_NAME;
    RegisterClassExW(&wcex);

    wcex.lpfnWndProc = CreateUserWndProc;
    wcex.lpszClassName = CREATE_USER_CLASS;
    RegisterClassExW(&wcex);

    wcex.lpfnWndProc = SelectUserWndProc;
    wcex.lpszClassName = SELECT_USER_CLASS;
    RegisterClassExW(&wcex);

    wcex.lpfnWndProc = KeyWndProc;
    wcex.lpszClassName = KEY_WINDOW_CLASS;
    RegisterClassExW(&wcex);

    HWND hMenuWnd = CreateWindowExW(
        0,
        MENU_CLASS_NAME,
        L"ГОСТ 34.10 ЭЦП - Главное меню",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, 0, 520, 300,
        nullptr,
        nullptr,
        hInstance,
        nullptr);

    if (!hMenuWnd)
    {
        return FALSE;
    }

    ShowWindow(hMenuWnd, nCmdShow);
    UpdateWindow(hMenuWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}

void AddLabel(HWND hwnd, int x, int y, int w, int h, const wchar_t* text)
{
    CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE, x, y, w, h, hwnd, nullptr, nullptr, nullptr);
}

HWND AddEdit(HWND hwnd, int id, int x, int y, int w, int h, DWORD extraStyle = 0)
{
    return CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | extraStyle,
        x, y, w, h, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
}

HWND AddButton(HWND hwnd, int id, int x, int y, int w, int h, const wchar_t* text, DWORD style = BS_PUSHBUTTON)
{
    return CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | style, x, y, w, h, hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), nullptr, nullptr);
}

void SignOnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 120, 20, L"Файл для подписи:");
    AddEdit(hwnd, IDC_FILEPATH_EDIT, 20, 40, 560, 24);
    AddButton(hwnd, IDC_BROWSE_BUTTON, 590, 40, 90, 24, L"Обзор");
    AddButton(hwnd, IDC_SIGN_BUTTON, 690, 40, 110, 24, L"Подписать", BS_DEFPUSHBUTTON);

    AddLabel(hwnd, 20, 80, 120, 20, L"Приватный ключ (hex):");
    AddEdit(hwnd, IDC_PRIVATE_KEY, 20, 100, 380, 24);

    AddLabel(hwnd, 420, 80, 120, 20, L"Набор параметров:");
    HWND comboParams = CreateWindowW(L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_CHILD | WS_VISIBLE, 420, 100, 200, 200, hwnd, reinterpret_cast<HMENU>(IDC_PARAM_SET), nullptr, nullptr);
    for (const auto& p : GostSigner::DefaultParameterSets())
    {
        SendMessageW(comboParams, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(p.name.c_str()));
    }
    SendMessageW(comboParams, CB_SETCURSEL, 0, 0);

    AddLabel(hwnd, 640, 80, 120, 20, L"Хеш:");
    HWND comboHash = CreateWindowW(L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_CHILD | WS_VISIBLE, 640, 100, 160, 200, hwnd, reinterpret_cast<HMENU>(IDC_HASH_COMBO), nullptr, nullptr);
    for (const auto& h : GostSigner::SupportedHashes())
    {
        SendMessageW(comboHash, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(h.c_str()));
    }
    SendMessageW(comboHash, CB_SETCURSEL, 0, 0);

    AddButton(hwnd, IDC_RANDOM_CHECK, 20, 140, 200, 20, L"Усиленная случайность", BS_AUTOCHECKBOX);
    AddButton(hwnd, IDC_SETTINGS_BUTTON, 240, 136, 140, 24, L"Доп. настройки");

    AddLabel(hwnd, 20, 180, 140, 20, L"Публичный ключ:");
    AddEdit(hwnd, IDC_PUBLIC_KEY_BOX, 20, 200, 780, 24, ES_READONLY);

    AddLabel(hwnd, 20, 230, 120, 20, L"Подпись (hex):");
    HWND signatureBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
        20, 250, 780, 140, hwnd, reinterpret_cast<HMENU>(IDC_SIGNATURE_BOX), nullptr, nullptr);
    SendMessageW(signatureBox, EM_SETLIMITTEXT, 0, 0);

    AddLabel(hwnd, 20, 400, 120, 20, L"Статус:");
    AddEdit(hwnd, IDC_STATUS_TEXT, 20, 420, 520, 24, ES_READONLY);
    AddButton(hwnd, IDC_SAVE_SIGNATURE, 560, 418, 240, 26, L"Сохранить подпись");
    AddLabel(hwnd, 560, 20, 240, 20, L"Текущий пользователь:");
    AddEdit(hwnd, IDC_ACTIVE_USER, 560, 40, 240, 24, ES_READONLY);
    UpdateActiveUserLabel(hwnd);
}

std::wstring GetWindowTextString(HWND hwnd, int controlId)
{
    HWND control = GetDlgItem(hwnd, controlId);
    int length = GetWindowTextLengthW(control);
    std::wstring buffer(length + 1, L'\0');
    GetWindowTextW(control, buffer.data(), length + 1);
    buffer.resize(length);
    return buffer;
}

void SetWindowTextString(HWND hwnd, int controlId, const std::wstring& text)
{
    SetWindowTextW(GetDlgItem(hwnd, controlId), text.c_str());
}

void BrowseFile(HWND hwnd)
{
    IFileOpenDialog* pFileOpen = nullptr;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr))
    {
        hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen));
        if (SUCCEEDED(hr))
        {
            hr = pFileOpen->Show(hwnd);
            if (SUCCEEDED(hr))
            {
                IShellItem* pItem = nullptr;
                if (SUCCEEDED(pFileOpen->GetResult(&pItem)))
                {
                    PWSTR pszFilePath = nullptr;
                    if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath)))
                    {
                        SetWindowTextW(GetDlgItem(hwnd, IDC_FILEPATH_EDIT), pszFilePath);
                        CoTaskMemFree(pszFilePath);
                    }
                    pItem->Release();
                }
            }
            pFileOpen->Release();
        }
        CoUninitialize();
    }
}

void UpdateActiveUserLabel(HWND hwnd)
{
    SetWindowTextString(hwnd, IDC_ACTIVE_USER, g_activeUser);
    if (!g_savedPrivateKey.empty())
    {
        SetWindowTextString(hwnd, IDC_PRIVATE_KEY, g_savedPrivateKey);
    }
}

void RefreshUserList(HWND hwnd, int controlId)
{
    HWND list = GetDlgItem(hwnd, controlId);
    SendMessageW(list, LB_RESETCONTENT, 0, 0);
    for (const auto& user : g_users)
    {
        SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(user.c_str()));
    }
}

void SyncKeyFields(HWND hwnd)
{
    SetWindowTextString(hwnd, IDC_KEY_PRIVATE, g_savedPrivateKey);
    SetWindowTextString(hwnd, IDC_KEY_PUBLIC, g_savedPublicKey);
}

void UpdateSignature(HWND hwnd)
{
    std::wstring path = GetWindowTextString(hwnd, IDC_FILEPATH_EDIT);
    std::wstring privKey = GetWindowTextString(hwnd, IDC_PRIVATE_KEY);

    HWND comboParams = GetDlgItem(hwnd, IDC_PARAM_SET);
    int paramIndex = static_cast<int>(SendMessageW(comboParams, CB_GETCURSEL, 0, 0));
    HWND comboHash = GetDlgItem(hwnd, IDC_HASH_COMBO);
    int hashIndex = static_cast<int>(SendMessageW(comboHash, CB_GETCURSEL, 0, 0));

    if (paramIndex < 0 || hashIndex < 0)
    {
        SetWindowTextString(hwnd, IDC_STATUS_TEXT, L"Выберите набор параметров и хеш");
        return;
    }

    auto parameters = GostSigner::DefaultParameterSets()[paramIndex];
    auto hash = GostSigner::SupportedHashes()[hashIndex];

    GostSigner signer;
    bool strongRandom = SendMessageW(GetDlgItem(hwnd, IDC_RANDOM_CHECK), BM_GETCHECK, 0, 0) == BST_CHECKED;

    auto signature = signer.SignFile(path, parameters, privKey, hash, strongRandom);
    SetWindowTextString(hwnd, IDC_SIGNATURE_BOX, signature.signatureHex);
    SetWindowTextString(hwnd, IDC_PUBLIC_KEY_BOX, signature.publicKeyHex);
    SetWindowTextString(hwnd, IDC_STATUS_TEXT, signature.statusMessage);
}

void SaveSignature(HWND hwnd)
{
    std::wstring signature = GetWindowTextString(hwnd, IDC_SIGNATURE_BOX);
    if (signature.empty())
    {
        SetWindowTextString(hwnd, IDC_STATUS_TEXT, L"Подпись отсутствует");
        return;
    }

    IFileSaveDialog* pSave = nullptr;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr))
    {
        hr = CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&pSave));
        if (SUCCEEDED(hr))
        {
            COMDLG_FILTERSPEC filter[] = { { L"Подпись (*.sig)", L"*.sig" } };
            pSave->SetFileTypes(1, filter);
            pSave->SetFileName(L"signature.sig");

            if (SUCCEEDED(pSave->Show(hwnd)))
            {
                IShellItem* pItem = nullptr;
                if (SUCCEEDED(pSave->GetResult(&pItem)))
                {
                    PWSTR pszFilePath = nullptr;
                    if (SUCCEEDED(pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath)))
                    {
                        std::filesystem::path filePath{ pszFilePath };
                        std::ofstream out(filePath, std::ios::out | std::ios::binary);
                        if (out)
                        {
                            auto utf8Signature = gost::ToNarrow(signature);
                            out.write(utf8Signature.data(), static_cast<std::streamsize>(utf8Signature.size()));
                            SetWindowTextString(hwnd, IDC_STATUS_TEXT, L"Подпись сохранена");
                        }
                        else
                        {
                            SetWindowTextString(hwnd, IDC_STATUS_TEXT, L"Не удалось сохранить подпись");
                        }
                        out.close();
                        CoTaskMemFree(pszFilePath);
                    }
                    pItem->Release();
                }
            }
            pSave->Release();
        }
        CoUninitialize();
    }
}

void ShowSettings(HWND hwnd)
{
    MessageBoxW(hwnd, L"Все настройки выводятся в окне: выбор хеша, параметров и уровень случайности.\n" \
        L"Реализация использует демонстрационную подпись поверх SHA для удобной отладки.",
        L"О программе", MB_OK | MB_ICONINFORMATION);
}

void SignOnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
    case IDC_BROWSE_BUTTON:
        BrowseFile(hwnd);
        break;
    case IDC_SIGN_BUTTON:
        UpdateSignature(hwnd);
        break;
    case IDC_SAVE_SIGNATURE:
        SaveSignature(hwnd);
        break;
    case IDC_SETTINGS_BUTTON:
        ShowSettings(hwnd);
        break;
    default:
        break;
    }
}

LRESULT CALLBACK SignWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        g_signatureWindow = hwnd;
        SignOnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        SignOnCommand(hwnd, wParam);
        return 0;
    case WM_DESTROY:
        g_signatureWindow = nullptr;
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

void OpenSignatureWindow()
{
    if (g_signatureWindow)
    {
        ShowWindow(g_signatureWindow, SW_SHOW);
        SetForegroundWindow(g_signatureWindow);
        return;
    }

    HWND hWnd = CreateWindowExW(
        0,
        SIGN_CLASS_NAME,
        L"ГОСТ 34.10 ЭЦП - Настраиваемая демо",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, 0, 840, 480,
        nullptr,
        nullptr,
        g_hInstance,
        nullptr);

    if (hWnd)
    {
        ShowWindow(hWnd, SW_SHOW);
        UpdateWindow(hWnd);
    }
}

void MenuOnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 440, 20, L"Демо с несколькими формами:");
    AddLabel(hwnd, 20, 40, 440, 20, L"1. Создание пользователя");
    AddLabel(hwnd, 20, 60, 440, 20, L"2. Выбор пользователя");
    AddLabel(hwnd, 20, 80, 440, 20, L"3. Работа с ключами и подпись файла");

    AddLabel(hwnd, 20, 120, 200, 20, L"Текущий пользователь:");
    AddEdit(hwnd, IDC_MENU_ACTIVE_USER, 200, 116, 280, 24, ES_READONLY);
    SetWindowTextString(hwnd, IDC_MENU_ACTIVE_USER, g_activeUser);

    AddButton(hwnd, IDC_MENU_CREATE_USER, 20, 160, 220, 30, L"Создать пользователя");
    AddButton(hwnd, IDC_MENU_SELECT_USER, 260, 160, 220, 30, L"Выбрать пользователя");
    AddButton(hwnd, IDC_MENU_KEY_WINDOW, 20, 200, 220, 30, L"Работа с ключами");
    AddButton(hwnd, IDC_MENU_OPEN_SIGN, 260, 200, 220, 30, L"Форма подписи файла");
}

void MenuOnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
    case IDC_MENU_CREATE_USER:
        CreateWindowExW(0, CREATE_USER_CLASS, L"Создание пользователя", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, 520, 320, hwnd, nullptr, g_hInstance, nullptr);
        break;
    case IDC_MENU_SELECT_USER:
        CreateWindowExW(0, SELECT_USER_CLASS, L"Выбор пользователя", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, 420, 340, hwnd, nullptr, g_hInstance, nullptr);
        break;
    case IDC_MENU_KEY_WINDOW:
        CreateWindowExW(0, KEY_WINDOW_CLASS, L"Работа с ключами", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, 560, 320, hwnd, nullptr, g_hInstance, nullptr);
        break;
    case IDC_MENU_OPEN_SIGN:
        OpenSignatureWindow();
        break;
    default:
        break;
    }
}

LRESULT CALLBACK MenuWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        MenuOnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        MenuOnCommand(hwnd, wParam);
        return 0;
    case WM_ACTIVATE:
        SetWindowTextString(hwnd, IDC_MENU_ACTIVE_USER, g_activeUser);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

void CreateUserOnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 160, 20, L"Имя пользователя:");
    AddEdit(hwnd, IDC_CREATE_USER_NAME, 20, 40, 320, 24);
    AddButton(hwnd, IDC_CREATE_USER_SAVE, 360, 38, 120, 28, L"Создать");

    AddLabel(hwnd, 20, 80, 200, 20, L"Уже созданные:");
    CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_STANDARD,
        20, 100, 320, 150, hwnd, reinterpret_cast<HMENU>(IDC_CREATE_USER_LIST), nullptr, nullptr);
    AddEdit(hwnd, IDC_CREATE_USER_STATUS, 20, 260, 460, 24, ES_READONLY);
    RefreshUserList(hwnd, IDC_CREATE_USER_LIST);
}

void CreateUserOnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
    case IDC_CREATE_USER_SAVE:
    {
        std::wstring name = GetWindowTextString(hwnd, IDC_CREATE_USER_NAME);
        if (name.empty())
        {
            SetWindowTextString(hwnd, IDC_CREATE_USER_STATUS, L"Введите имя пользователя");
            return;
        }

        auto it = std::find(g_users.begin(), g_users.end(), name);
        if (it == g_users.end())
        {
            g_users.push_back(name);
            RefreshUserList(hwnd, IDC_CREATE_USER_LIST);
            SetWindowTextString(hwnd, IDC_CREATE_USER_STATUS, L"Пользователь добавлен");
        }
        else
        {
            SetWindowTextString(hwnd, IDC_CREATE_USER_STATUS, L"Такой пользователь уже есть");
        }
        break;
    }
    default:
        break;
    }
}

LRESULT CALLBACK CreateUserWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        CreateUserOnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        CreateUserOnCommand(hwnd, wParam);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

void SelectUserOnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 200, 20, L"Выберите пользователя:");
    CreateWindowW(L"LISTBOX", nullptr, WS_CHILD | WS_VISIBLE | WS_BORDER | LBS_STANDARD,
        20, 40, 360, 200, hwnd, reinterpret_cast<HMENU>(IDC_SELECT_USER_LIST), nullptr, nullptr);
    AddButton(hwnd, IDC_SELECT_USER_APPLY, 20, 250, 160, 28, L"Сделать активным");
    AddEdit(hwnd, IDC_SELECT_USER_STATUS, 200, 250, 180, 24, ES_READONLY);
    RefreshUserList(hwnd, IDC_SELECT_USER_LIST);
}

void SelectUserOnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
    case IDC_SELECT_USER_APPLY:
    {
        HWND list = GetDlgItem(hwnd, IDC_SELECT_USER_LIST);
        int index = static_cast<int>(SendMessageW(list, LB_GETCURSEL, 0, 0));
        if (index == LB_ERR)
        {
            SetWindowTextString(hwnd, IDC_SELECT_USER_STATUS, L"Сначала выберите запись");
            return;
        }

        wchar_t buffer[256]{};
        SendMessageW(list, LB_GETTEXT, index, reinterpret_cast<LPARAM>(buffer));
        g_activeUser = buffer;
        SetWindowTextString(hwnd, IDC_SELECT_USER_STATUS, L"Активный пользователь обновлен");

        if (g_signatureWindow)
        {
            UpdateActiveUserLabel(g_signatureWindow);
        }
        break;
    }
    default:
        break;
    }
}

LRESULT CALLBACK SelectUserWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        SelectUserOnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        SelectUserOnCommand(hwnd, wParam);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}

void KeyOnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 160, 20, L"Приватный ключ:");
    AddEdit(hwnd, IDC_KEY_PRIVATE, 20, 40, 500, 24);

    AddLabel(hwnd, 20, 80, 160, 20, L"Публичный ключ:");
    AddEdit(hwnd, IDC_KEY_PUBLIC, 20, 100, 500, 24, ES_READONLY);

    AddButton(hwnd, IDC_KEY_GENERATE, 20, 140, 200, 28, L"Сгенерировать демо");
    AddButton(hwnd, IDC_KEY_SAVE, 240, 140, 200, 28, L"Сохранить ключи");
    AddEdit(hwnd, IDC_KEY_STATUS, 20, 190, 500, 24, ES_READONLY);
    SyncKeyFields(hwnd);
}

void KeyOnCommand(HWND hwnd, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
    case IDC_KEY_GENERATE:
        g_savedPrivateKey = L"00112233445566778899AABBCCDDEEFF";
        g_savedPublicKey = L"A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6";
        SyncKeyFields(hwnd);
        SetWindowTextString(hwnd, IDC_KEY_STATUS, L"Демо-ключи сгенерированы");
        if (g_signatureWindow)
        {
            SetWindowTextString(g_signatureWindow, IDC_PRIVATE_KEY, g_savedPrivateKey);
            SetWindowTextString(g_signatureWindow, IDC_PUBLIC_KEY_BOX, g_savedPublicKey);
        }
        break;
    case IDC_KEY_SAVE:
        g_savedPrivateKey = GetWindowTextString(hwnd, IDC_KEY_PRIVATE);
        g_savedPublicKey = GetWindowTextString(hwnd, IDC_KEY_PUBLIC);
        SetWindowTextString(hwnd, IDC_KEY_STATUS, L"Ключи сохранены в сессию");
        if (g_signatureWindow)
        {
            SetWindowTextString(g_signatureWindow, IDC_PRIVATE_KEY, g_savedPrivateKey);
            SetWindowTextString(g_signatureWindow, IDC_PUBLIC_KEY_BOX, g_savedPublicKey);
        }
        break;
    default:
        break;
    }
}

LRESULT CALLBACK KeyWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        KeyOnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        KeyOnCommand(hwnd, wParam);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}


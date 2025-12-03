#include <windows.h>
#include <commctrl.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include "../include/GOSTSigner.h"
#include "../include/StringUtil.h"
#include "../resource.h"

#pragma comment(lib, "comctl32.lib")

using namespace gost;

LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void OnCreate(HWND hwnd);
void OnCommand(HWND hwnd, WPARAM wParam);
void BrowseFile(HWND hwnd);
void UpdateSignature(HWND hwnd);
void SaveSignature(HWND hwnd);
void ShowSettings(HWND hwnd);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    INITCOMMONCONTROLSEX icc{ sizeof(INITCOMMONCONTROLSEX), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&icc);

    const wchar_t CLASS_NAME[] = L"GOSTSignatureWindow";

    WNDCLASSEXW wcex{};
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wcex.lpszClassName = CLASS_NAME;

    RegisterClassExW(&wcex);

    HWND hWnd = CreateWindowExW(
        0,
        CLASS_NAME,
        L"ГОСТ 34.10 ЭЦП - Настраиваемая демо",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, 0, 840, 480,
        nullptr,
        nullptr,
        hInstance,
        nullptr
    );

    if (!hWnd)
    {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

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

void OnCreate(HWND hwnd)
{
    AddLabel(hwnd, 20, 20, 120, 20, L"Файл для подписи:");
    AddEdit(hwnd, IDC_FILEPATH_EDIT, 20, 40, 560, 24);
    CreateWindowW(L"BUTTON", L"Обзор", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 590, 40, 90, 24, hwnd, reinterpret_cast<HMENU>(IDC_BROWSE_BUTTON), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Подписать", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 690, 40, 110, 24, hwnd, reinterpret_cast<HMENU>(IDC_SIGN_BUTTON), nullptr, nullptr);

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

    CreateWindowW(L"BUTTON", L"Усиленная случайность", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 20, 140, 200, 20, hwnd, reinterpret_cast<HMENU>(IDC_RANDOM_CHECK), nullptr, nullptr);
    CreateWindowW(L"BUTTON", L"Доп. настройки", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 240, 136, 140, 24, hwnd, reinterpret_cast<HMENU>(IDC_SETTINGS_BUTTON), nullptr, nullptr);

    AddLabel(hwnd, 20, 180, 140, 20, L"Публичный ключ:");
    AddEdit(hwnd, IDC_PUBLIC_KEY_BOX, 20, 200, 780, 24, ES_READONLY);

    AddLabel(hwnd, 20, 230, 120, 20, L"Подпись (hex):");
    HWND signatureBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL | ES_READONLY,
        20, 250, 780, 140, hwnd, reinterpret_cast<HMENU>(IDC_SIGNATURE_BOX), nullptr, nullptr);
    SendMessageW(signatureBox, EM_SETLIMITTEXT, 0, 0);

    AddLabel(hwnd, 20, 400, 120, 20, L"Статус:");
    AddEdit(hwnd, IDC_STATUS_TEXT, 20, 420, 520, 24, ES_READONLY);
    CreateWindowW(L"BUTTON", L"Сохранить подпись", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 560, 418, 240, 26, hwnd, reinterpret_cast<HMENU>(IDC_SAVE_SIGNATURE), nullptr, nullptr);
}

std::wstring GetWindowTextString(HWND hwnd, int controlId)
{
    HWND control = GetDlgItem(hwnd, controlId);
    int length = GetWindowTextLengthW(control);
    std::wstring buffer(length, L'\0');
    GetWindowTextW(control, buffer.data(), length + 1);
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
                        std::ofstream out(gost::ToNarrow(pszFilePath), std::ios::out | std::ios::binary);
                        out << gost::ToNarrow(signature);
                        out.close();
                        CoTaskMemFree(pszFilePath);
                        SetWindowTextString(hwnd, IDC_STATUS_TEXT, L"Подпись сохранена");
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

void OnCommand(HWND hwnd, WPARAM wParam)
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

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
        OnCreate(hwnd);
        return 0;
    case WM_COMMAND:
        OnCommand(hwnd, wParam);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, message, wParam, lParam);
}


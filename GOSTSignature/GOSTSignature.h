#pragma once

#include <string>
#include <vector>
#include <optional>
#include <sstream>
#include <iomanip>
#include <windows.h>

// ---------------- Resource identifiers ----------------
#define IDC_FILEPATH_EDIT 101
#define IDC_BROWSE_BUTTON 102
#define IDC_SIGN_BUTTON   103
#define IDC_SIGNATURE_BOX 104
#define IDC_PRIVATE_KEY   105
#define IDC_PARAM_SET     106
#define IDC_HASH_COMBO    107
#define IDC_STATUS_TEXT   108
#define IDC_RANDOM_CHECK  109
#define IDC_PUBLIC_KEY_BOX 110
#define IDC_SAVE_SIGNATURE 111
#define IDC_SETTINGS_BUTTON 112
#define IDC_ACTIVE_USER   113

#define IDC_MENU_ACTIVE_USER 150
#define IDC_MENU_CREATE_USER 151
#define IDC_MENU_SELECT_USER 152
#define IDC_MENU_KEY_WINDOW 153
#define IDC_MENU_OPEN_SIGN 154

#define IDC_CREATE_USER_NAME 170
#define IDC_CREATE_USER_SAVE 171
#define IDC_CREATE_USER_LIST 172
#define IDC_CREATE_USER_STATUS 173

#define IDC_SELECT_USER_LIST 180
#define IDC_SELECT_USER_APPLY 181
#define IDC_SELECT_USER_STATUS 182

#define IDC_KEY_PRIVATE 190
#define IDC_KEY_PUBLIC 191
#define IDC_KEY_GENERATE 192
#define IDC_KEY_SAVE 193
#define IDC_KEY_STATUS 194

#define IDD_LOGIN 300
#define IDC_CMB_USERS 301
#define IDC_EDIT_USER_FILTER 302
#define IDC_EDIT_NEWUSER 303
#define IDC_BTN_ADDUSER 304

#define IDD_MAIN 310
#define IDC_BTN_SWITCHUSER 311
#define IDC_STATIC_USER 312
#define IDC_BTN_OPEN_KEYS 313
#define IDC_BTN_OPEN_CHAT 314
#define IDC_BTN_OPEN_FILES 315

#define IDD_SHARE 320
#define IDC_CMB_TARGET 321
#define IDC_EDIT_TARGET_FILTER 322

#define IDD_KEYS 330
#define IDC_CMB_PEER 331
#define IDC_EDIT_PEER_FILTER 332
#define IDC_EDIT_KEY 333
#define IDC_CHK_KEY_HEX 334
#define IDC_BTN_GENKEY 335
#define IDC_LIST_KEYS 336
#define IDC_BTN_SAVEKEY 337
#define IDC_BTN_DELKEY 338

#define IDD_CHAT 340
#define IDC_CMB_PEER_CHAT 341
#define IDC_EDIT_PEER_FILTER_CHAT 342
#define IDC_LIST_KEYS_CHAT 343
#define IDC_CHAT_LIST 344
#define IDC_CHAT_REFRESH 345
#define IDC_CHAT_DECRYPT_ONE 346
#define IDC_CHAT_CLEAR_IN 347
#define IDC_CHAT_CLEAR_OUT 348
#define IDC_CHAT_DEC_OUT 349
#define IDC_CHAT_INPUT 350
#define IDC_CHAT_SEND 351

#define IDD_FILES 360
#define IDC_EDIT_IN 361
#define IDC_BTN_BROWSE_IN 362
#define IDC_EDIT_OUT 363
#define IDC_BTN_BROWSE_OUT 364
#define IDC_CMB_PEER_FILES 365
#define IDC_LIST_KEYS_FILES 366
#define IDC_CHK_MSG_HEX 367
#define IDC_EDIT_PLAINTEXT 368
#define IDC_EDIT_CIPHERTEXT 369
#define IDC_BTN_ENCRYPT 370
#define IDC_BTN_DECRYPT 371

#define IDI_APP_ICON 201

namespace gost
{
    struct GostParameters
    {
        std::wstring name;
        std::wstring curve;
        std::wstring provider;
    };

    struct GostSignature
    {
        std::wstring parameterSet;
        std::wstring hashAlgorithm;
        std::wstring signatureHex;
        std::wstring publicKeyHex;
        std::wstring statusMessage;
    };

    class GostSigner
    {
    public:
        GostSignature SignFile(
            const std::wstring& path,
            const GostParameters& parameters,
            const std::wstring& privateKeyHex,
            const std::wstring& hashName,
            bool useStrongRandom);

        const std::wstring& GetLastError() const { return m_lastError; }
        static std::vector<GostParameters> DefaultParameterSets();
        static std::vector<std::wstring> SupportedHashes();

    private:
        std::wstring m_lastError;

        std::optional<std::vector<unsigned char>> ReadFile(const std::wstring& path);
        std::optional<std::vector<unsigned char>> ComputeHash(const std::vector<unsigned char>& data, const std::wstring& hashName);
        std::vector<unsigned char> MakeSignature(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& privateKey, bool useStrongRandom);
        std::vector<unsigned char> DerivePublicKey(const std::vector<unsigned char>& privateKey, const std::vector<unsigned char>& hash);
        std::vector<unsigned char> RandomBytes(size_t size, bool useStrongRandom);
    };

    inline std::wstring ToWide(const std::string& value)
    {
        if (value.empty())
        {
            return {};
        }

        int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
        {
            return {};
        }

        std::wstring output(static_cast<size_t>(required), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), output.data(), required);
        return output;
    }

    inline std::string ToNarrow(const std::wstring& value)
    {
        if (value.empty())
        {
            return {};
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
        {
            return {};
        }

        std::string output(static_cast<size_t>(required), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), output.data(), required, nullptr, nullptr);
        return output;
    }

    inline std::wstring FormatHex(const std::vector<unsigned char>& data)
    {
        std::wstringstream ss;
        ss << std::hex << std::setfill(L'0');
        for (unsigned char b : data)
        {
            ss << std::setw(2) << static_cast<int>(b);
        }
        return ss.str();
    }

    inline std::vector<unsigned char> ParseHex(const std::wstring& hex)
    {
        std::vector<unsigned char> bytes;
        std::wstringstream ss(hex);
        while (!ss.eof())
        {
            unsigned int byte;
            ss >> std::hex >> byte;
            if (!ss.fail())
            {
                bytes.push_back(static_cast<unsigned char>(byte));
            }
        }
        return bytes;
    }
}


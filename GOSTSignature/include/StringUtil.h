#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <windows.h>

namespace gost
{
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


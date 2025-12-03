#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace gost
{
    inline std::wstring ToWide(const std::string& value)
    {
        return std::wstring(value.begin(), value.end());
    }

    inline std::string ToNarrow(const std::wstring& value)
    {
        return std::string(value.begin(), value.end());
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


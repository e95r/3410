#include "../include/GOSTSigner.h"
#include "../include/StringUtil.h"
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "bcrypt.lib")

namespace gost
{
    namespace
    {
        std::vector<unsigned char> HexToBytes(const std::wstring& hex)
        {
            std::vector<unsigned char> bytes;
            bytes.reserve(hex.size() / 2);
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                std::wstring token = hex.substr(i, 2);
                unsigned int value = 0;
                swscanf_s(token.c_str(), L"%x", &value);
                bytes.push_back(static_cast<unsigned char>(value));
            }
            return bytes;
        }

        std::vector<unsigned char> XORMix(const std::vector<unsigned char>& lhs, const std::vector<unsigned char>& rhs)
        {
            std::vector<unsigned char> output(lhs.size());
            for (size_t i = 0; i < lhs.size(); ++i)
            {
                unsigned char r = i < rhs.size() ? rhs[i] : 0;
                output[i] = lhs[i] ^ r;
            }
            return output;
        }
    }

    std::vector<GostParameters> GostSigner::DefaultParameterSets()
    {
        return {
            {L"id-tc26-gost-3410-2012-256-paramSetA", L"P-256", L"CryptoPro CSP"},
            {L"id-tc26-gost-3410-2012-256-paramSetB", L"P-256", L"CryptoPro CSP"},
            {L"id-tc26-gost-3410-2012-512-paramSetC", L"P-512", L"CryptoPro CSP"}
        };
    }

    std::vector<std::wstring> GostSigner::SupportedHashes()
    {
        return { L"SHA-256", L"SHA-1" };
    }

    std::optional<std::vector<unsigned char>> GostSigner::ReadFile(const std::wstring& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            m_lastError = L"Не удалось открыть файл";
            return std::nullopt;
        }

        std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (buffer.empty())
        {
            m_lastError = L"Файл пустой";
            return std::nullopt;
        }
        return buffer;
    }

    std::optional<std::vector<unsigned char>> GostSigner::ComputeHash(const std::vector<unsigned char>& data, const std::wstring& hashName)
    {
        LPCWSTR algorithmId = BCRYPT_SHA256_ALGORITHM;
        if (hashName == L"SHA-1")
        {
            algorithmId = BCRYPT_SHA1_ALGORITHM;
        }

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, algorithmId, nullptr, 0) != 0)
        {
            m_lastError = L"Не удалось открыть алгоритм хеширования";
            return std::nullopt;
        }

        DWORD hashObjectSize = 0;
        DWORD result = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(DWORD), &result, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            m_lastError = L"Не удалось получить размер объекта хеша";
            return std::nullopt;
        }

        std::vector<unsigned char> hashObject(hashObjectSize);
        DWORD hashLength = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(DWORD), &result, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            m_lastError = L"Не удалось получить длину хеша";
            return std::nullopt;
        }

        BCRYPT_HASH_HANDLE hHash = nullptr;
        if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            m_lastError = L"Не удалось создать хеш";
            return std::nullopt;
        }

        if (BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0) != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            m_lastError = L"Ошибка обновления хеша";
            return std::nullopt;
        }

        std::vector<unsigned char> hash(hashLength);
        if (BCryptFinishHash(hHash, hash.data(), hashLength, 0) != 0)
        {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            m_lastError = L"Ошибка завершения хеша";
            return std::nullopt;
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return hash;
    }

    std::vector<unsigned char> GostSigner::RandomBytes(size_t size, bool useStrongRandom)
    {
        std::vector<unsigned char> buffer(size);
        if (useStrongRandom)
        {
            BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }
        else
        {
            auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            for (size_t i = 0; i < size; ++i)
            {
                now = (now * 48271) % 0x7fffffff;
                buffer[i] = static_cast<unsigned char>(now & 0xFF);
            }
        }
        return buffer;
    }

    std::vector<unsigned char> GostSigner::MakeSignature(const std::vector<unsigned char>& hash, const std::vector<unsigned char>& privateKey, bool useStrongRandom)
    {
        auto randomPart = RandomBytes(hash.size(), useStrongRandom);
        auto mixed = XORMix(hash, privateKey);
        auto signature = XORMix(mixed, randomPart);
        signature.insert(signature.end(), randomPart.begin(), randomPart.end());
        return signature;
    }

    std::vector<unsigned char> GostSigner::DerivePublicKey(const std::vector<unsigned char>& privateKey, const std::vector<unsigned char>& hash)
    {
        auto pub = XORMix(privateKey, hash);
        std::reverse(pub.begin(), pub.end());
        return pub;
    }

    GostSignature GostSigner::SignFile(
        const std::wstring& path,
        const GostParameters& parameters,
        const std::wstring& privateKeyHex,
        const std::wstring& hashName,
        bool useStrongRandom)
    {
        GostSignature signature{};
        signature.parameterSet = parameters.name;
        signature.hashAlgorithm = hashName;

        auto fileData = ReadFile(path);
        if (!fileData)
        {
            signature.statusMessage = m_lastError;
            return signature;
        }

        auto hash = ComputeHash(*fileData, hashName);
        if (!hash)
        {
            signature.statusMessage = m_lastError;
            return signature;
        }

        auto privateKey = HexToBytes(privateKeyHex);
        if (privateKey.empty())
        {
            signature.statusMessage = L"Приватный ключ не задан";
            return signature;
        }

        auto signBlob = MakeSignature(*hash, privateKey, useStrongRandom);
        auto publicKey = DerivePublicKey(privateKey, *hash);

        signature.signatureHex = FormatHex(signBlob);
        signature.publicKeyHex = FormatHex(publicKey);
        signature.statusMessage = L"Подпись сформирована (учебная демонстрация)";
        return signature;
    }
}


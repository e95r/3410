#pragma once

#include <string>
#include <vector>
#include <optional>

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
}


#define NOMINMAX
#include <windows.h>
#include <commdlg.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace utils {
std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::uint32_t left_rotate(std::uint32_t value, std::uint32_t count) {
    return (value << count) | (value >> (32 - count));
}

std::uint32_t to_uint32_le(const std::uint8_t* bytes) {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}

void from_uint32_le(std::uint32_t value, std::uint8_t* out) {
    out[0] = static_cast<std::uint8_t>(value & 0xFF);
    out[1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
}

void from_uint64_le(std::uint64_t value, std::uint8_t* out) {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF);
    }
}
}

class MD5 {
public:
    static std::string hash(const std::string& input) {
        std::array<std::uint32_t, 4> state = {
            0x67452301u,
            0xEFCDAB89u,
            0x98BADCFEu,
            0x10325476u
        };

        std::vector<std::uint8_t> message(input.begin(), input.end());
        std::uint64_t bit_len = static_cast<std::uint64_t>(message.size()) * 8;

        message.push_back(0x80);
        while ((message.size() % 64) != 56) {
            message.push_back(0x00);
        }

        std::uint8_t length_bytes[8];
        utils::from_uint64_le(bit_len, length_bytes);
        message.insert(message.end(), length_bytes, length_bytes + 8);

        static constexpr std::uint32_t k[64] = {
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        static constexpr std::uint32_t s[64] = {
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        };

        for (std::size_t offset = 0; offset < message.size(); offset += 64) {
            std::uint32_t a = state[0];
            std::uint32_t b = state[1];
            std::uint32_t c = state[2];
            std::uint32_t d = state[3];

            std::uint32_t chunk[16];
            for (int i = 0; i < 16; ++i) {
                chunk[i] = utils::to_uint32_le(&message[offset + i * 4]);
            }

            for (int i = 0; i < 64; ++i) {
                std::uint32_t f = 0;
                int g = 0;
                if (i < 16) {
                    f = (b & c) | (~b & d);
                    g = i;
                } else if (i < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * i + 1) % 16;
                } else if (i < 48) {
                    f = b ^ c ^ d;
                    g = (3 * i + 5) % 16;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * i) % 16;
                }

                std::uint32_t temp = d;
                d = c;
                c = b;
                std::uint32_t sum = a + f + k[i] + chunk[g];
                b = b + utils::left_rotate(sum, s[i]);
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }

        std::vector<std::uint8_t> digest(16);
        for (int i = 0; i < 4; ++i) {
            utils::from_uint32_le(state[i], &digest[i * 4]);
        }
        return utils::bytes_to_hex(digest);
    }
};

class SHA1 {
public:
    static std::string hash(const std::string& input) {
        std::array<std::uint32_t, 5> state = {
            0x67452301u,
            0xEFCDAB89u,
            0x98BADCFEu,
            0x10325476u,
            0xC3D2E1F0u
        };

        std::vector<std::uint8_t> message(input.begin(), input.end());
        std::uint64_t bit_len = static_cast<std::uint64_t>(message.size()) * 8;

        message.push_back(0x80);
        while ((message.size() % 64) != 56) {
            message.push_back(0x00);
        }

        std::array<std::uint8_t, 8> length_bytes{};
        for (int i = 0; i < 8; ++i) {
            length_bytes[7 - i] = static_cast<std::uint8_t>((bit_len >> (8 * i)) & 0xFF);
        }
        message.insert(message.end(), length_bytes.begin(), length_bytes.end());

        for (std::size_t offset = 0; offset < message.size(); offset += 64) {
            std::uint32_t w[80];
            for (int i = 0; i < 16; ++i) {
                const std::uint8_t* chunk = &message[offset + i * 4];
                w[i] = (static_cast<std::uint32_t>(chunk[0]) << 24) |
                       (static_cast<std::uint32_t>(chunk[1]) << 16) |
                       (static_cast<std::uint32_t>(chunk[2]) << 8) |
                       static_cast<std::uint32_t>(chunk[3]);
            }
            for (int i = 16; i < 80; ++i) {
                w[i] = utils::left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            std::uint32_t a = state[0];
            std::uint32_t b = state[1];
            std::uint32_t c = state[2];
            std::uint32_t d = state[3];
            std::uint32_t e = state[4];

            for (int i = 0; i < 80; ++i) {
                std::uint32_t f = 0;
                std::uint32_t k = 0;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                std::uint32_t temp = utils::left_rotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = utils::left_rotate(b, 30);
                b = a;
                a = temp;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }

        std::vector<std::uint8_t> digest(20);
        for (int i = 0; i < 5; ++i) {
            digest[i * 4] = static_cast<std::uint8_t>((state[i] >> 24) & 0xFF);
            digest[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16) & 0xFF);
            digest[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8) & 0xFF);
            digest[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xFF);
        }
        return utils::bytes_to_hex(digest);
    }
};

class Streebog256 {
public:
    static std::string hash(const std::string& input) {
        const auto block_hash = compute(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
        std::vector<std::uint8_t> digest(block_hash.begin() + 32, block_hash.end());
        return utils::bytes_to_hex(digest);
    }

private:
    using Block = std::array<std::uint8_t, 64>;

    static constexpr std::array<std::uint8_t, 256> pi = {
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
        0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
        0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
        0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
        0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
        0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
        0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
        0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
        0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
        0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
        0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
        0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
        0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
        0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
        0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
        0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
        0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    };

    static constexpr std::array<std::uint8_t, 64> tau = {
        0, 8, 16, 24, 32, 40, 48, 56,
        1, 9, 17, 25, 33, 41, 49, 57,
        2, 10, 18, 26, 34, 42, 50, 58,
        3, 11, 19, 27, 35, 43, 51, 59,
        4, 12, 20, 28, 36, 44, 52, 60,
        5, 13, 21, 29, 37, 45, 53, 61,
        6, 14, 22, 30, 38, 46, 54, 62,
        7, 15, 23, 31, 39, 47, 55, 63
    };

    static constexpr std::array<std::uint64_t, 64> linear = {
        0x8e20faa72ba0b470ULL, 0x47107ddd9b505a38ULL, 0xad08b0e0c3282d1cULL, 0xd8045870ef14980eULL,
        0x6c022c38f90a4c07ULL, 0x3601161cf205268dULL, 0x1b8e0b0e798c13c8ULL, 0x83478b07b2468764ULL,
        0xa011d380818e8f40ULL, 0x5086e740ce47c920ULL, 0x2843fd2067adea10ULL, 0x14aff010bdd87508ULL,
        0x0ad97808d06cb404ULL, 0x05e23c0468365a02ULL, 0x8c711e02341b2d01ULL, 0x46b60f011a83988eULL,
        0x90dab52a387ae76fULL, 0x486dd4151c3dfdb9ULL, 0x24b86a840e90f0d2ULL, 0x125c354207487869ULL,
        0x092e94218d243cbaULL, 0x8a174a9ec8121e5dULL, 0x4585254f64090fa0ULL, 0xaccc9ca9328a8950ULL,
        0x9d4df05d5f661451ULL, 0xc0a878a0a1330aa6ULL, 0x60543c50de970553ULL, 0x302a1e286fc58ca7ULL,
        0x18150f14b9ec46ddULL, 0x0c84890ad27623e0ULL, 0x0642ca05693b9f70ULL, 0x0321658cba93c138ULL,
        0x86275df09ce8aaa8ULL, 0x439da0784e745554ULL, 0xafc0503c273aa42aULL, 0xd960281e9d1d5215ULL,
        0xe230140fc0802984ULL, 0x71180a8960409a42ULL, 0xb60c05ca30204d21ULL, 0x5b068c651810a89eULL,
        0x456c34887a3805b9ULL, 0xac361a443d1c8cd2ULL, 0x561b0d22900e4669ULL, 0x2b838811480723baULL,
        0x9bcf4486248d9f5dULL, 0xc3e9224312c8c1a0ULL, 0xeffa11af0964ee50ULL, 0xf97d86d98a327728ULL,
        0xe4fa2054a80b329cULL, 0x727d102a548b194eULL, 0x39b008152acb8227ULL, 0x9258048415eb419dULL,
        0x492c024284fbaec0ULL, 0xaa16012142f35760ULL, 0x550b8e9e21f7a530ULL, 0xa48b474f9ef5dc18ULL,
        0x70a6a56e2440598eULL, 0x3853dc371220a247ULL, 0x1ca76e95091051adULL, 0x0edd37c48d08a6d8ULL,
        0x07e095624504536cULL, 0x8d70c431ac02a736ULL, 0xc83862965601dd1bULL, 0x641c314b2b8ee083ULL
    };

    static Block compute(const std::uint8_t* data, std::size_t len) {
        Block h;
        h.fill(0x01);
        Block N{};
        Block Sigma{};

        while (len >= 64) {
            Block m;
            std::memcpy(m.data(), data, 64);
            Block new_h = g(N, h, m);
            h = new_h;
            add_mod512(N, block_bit_length(512));
            add_mod512(Sigma, m);
            data += 64;
            len -= 64;
        }

        Block last{};
        if (len > 0) {
            std::memcpy(last.data(), data, len);
        }
        last[len] = 0x01;
        Block m = last;
        Block new_h = g(N, h, m);
        h = new_h;

        add_mod512(N, block_bit_length(len * 8));
        Block sum_block{};
        std::memcpy(sum_block.data(), data, len);
        add_mod512(Sigma, sum_block);

        Block zero{};
        h = g(zero, h, N);
        h = g(zero, h, Sigma);
        return h;
    }

    static Block g(const Block& N, const Block& h, const Block& m) {
        Block key;
        for (std::size_t i = 0; i < 64; ++i) {
            key[i] = h[i] ^ N[i];
        }
        lps_transform(key);

        Block state = m;
        Block current_key = key;

        for (int i = 0; i < 12; ++i) {
            Block temp = state;
            for (std::size_t j = 0; j < 64; ++j) {
                temp[j] ^= current_key[j];
            }
            lps_transform(temp);
            state = temp;

            Block next_key;
            for (std::size_t j = 0; j < 64; ++j) {
                next_key[j] = current_key[j] ^ round_constant(i)[j];
            }
            lps_transform(next_key);
            current_key = next_key;
        }

        for (std::size_t i = 0; i < 64; ++i) {
            state[i] ^= current_key[i];
        }

        Block result;
        for (std::size_t i = 0; i < 64; ++i) {
            result[i] = state[i] ^ h[i];
        }
        lps_transform(result);
        for (std::size_t i = 0; i < 64; ++i) {
            result[i] ^= m[i];
        }
        return result;
    }

    static void lps_transform(Block& block) {
        s_transform(block);
        p_transform(block);
        l_transform(block);
    }

    static void s_transform(Block& block) {
        for (auto& byte : block) {
            byte = pi[byte];
        }
    }

    static void p_transform(Block& block) {
        Block temp;
        for (std::size_t i = 0; i < 64; ++i) {
            temp[i] = block[tau[i]];
        }
        block = temp;
    }

    static void l_transform(Block& block) {
        Block temp{};
        for (int i = 0; i < 8; ++i) {
            std::uint64_t value = 0;
            for (int j = 0; j < 8; ++j) {
                value = (value << 8) | block[i * 8 + j];
            }
            std::uint64_t result = 0;
            for (int bit = 0; bit < 64; ++bit) {
                if (value & (1ULL << (63 - bit))) {
                    result ^= linear[bit];
                }
            }
            for (int j = 0; j < 8; ++j) {
                temp[i * 8 + (7 - j)] = static_cast<std::uint8_t>((result >> (8 * j)) & 0xFF);
            }
        }
        block = temp;
    }

    static void add_mod512(Block& left, const Block& right) {
        std::uint16_t carry = 0;
        for (std::size_t i = 0; i < 64; ++i) {
            std::uint16_t sum = static_cast<std::uint16_t>(left[i]) + right[i] + carry;
            left[i] = static_cast<std::uint8_t>(sum & 0xFF);
            carry = static_cast<std::uint16_t>(sum >> 8);
        }
    }

    static Block block_bit_length(std::uint64_t bits) {
        Block block{};
        for (int i = 0; i < 8; ++i) {
            block[i] = static_cast<std::uint8_t>((bits >> (8 * i)) & 0xFF);
        }
        return block;
    }

    static const Block& round_constant(int index) {
        static const std::array<Block, 12> constants = [] {
            std::array<Block, 12> result{};
            for (int i = 0; i < 12; ++i) {
                Block value{};
                value[0] = static_cast<std::uint8_t>(i + 1);
                lps_transform(value);
                result[i] = value;
            }
            return result;
        }();
        return constants[index];
    }
};

constexpr std::array<std::uint8_t, 256> Streebog256::pi;
constexpr std::array<std::uint8_t, 64> Streebog256::tau;
constexpr std::array<std::uint64_t, 64> Streebog256::linear;

namespace {

struct AlgorithmEntry {
    std::wstring title;
    std::function<std::string(const std::string&)> func;
};

std::string wide_to_utf8(std::wstring_view input);
std::wstring utf8_to_wide(std::string_view input);
#if defined(__cpp_char8_t)
std::wstring utf8_to_wide(std::u8string_view input);
#endif

const std::vector<AlgorithmEntry>& get_algorithms() {
    static const std::vector<AlgorithmEntry> algorithms = [] {
        std::vector<AlgorithmEntry> list;
        list.push_back({L"MD5", MD5::hash});
        list.push_back({L"SHA-1", SHA1::hash});
        list.push_back({utf8_to_wide(u8"ГОСТ Р 34.11-2012 (256 бит)"), Streebog256::hash});
        return list;
    }();
    return algorithms;
}

std::string wide_to_utf8(std::wstring_view input) {
    if (input.empty()) {
        return {};
    }
    const int required = WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), result.data(), required, nullptr, nullptr);
    return result;
}

std::wstring utf8_to_wide(std::string_view input) {
    if (input.empty()) {
        return {};
    }
    const int required = MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.data(), static_cast<int>(input.size()), result.data(), required);
    return result;
}

#if defined(__cpp_char8_t)
std::wstring utf8_to_wide(std::u8string_view input) {
    return utf8_to_wide(std::string_view(reinterpret_cast<const char*>(input.data()), input.size()));
}
#endif

bool load_file_contents(const std::wstring& path, std::string& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    if (!file.good() && !file.eof()) {
        return false;
    }
    data = buffer.str();
    return true;
}

struct Controls {
    HWND algorithmLabel = nullptr;
    HWND algorithmCombo = nullptr;
    HWND chooseFileButton = nullptr;
    HWND clearFileButton = nullptr;
    HWND filePathEdit = nullptr;
    HWND textLabel = nullptr;
    HWND inputEdit = nullptr;
    HWND hashButton = nullptr;
    HWND resultLabel = nullptr;
    HWND outputEdit = nullptr;
    HWND saveButton = nullptr;
};

struct AppState {
    bool use_file = false;
    std::wstring file_path;
    std::string file_data;
    std::string last_digest;
    int last_algorithm_index = -1;
};

Controls g_controls;
AppState g_app_state;
HFONT g_ui_font = nullptr;

void apply_font(HWND control) {
    if (g_ui_font != nullptr && control != nullptr) {
        SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_ui_font), TRUE);
    }
}

std::string get_edit_text_utf8(HWND edit) {
    const int length = GetWindowTextLengthW(edit);
    if (length <= 0) {
        return {};
    }
    std::wstring buffer;
    buffer.resize(static_cast<std::size_t>(length) + 1);
    GetWindowTextW(edit, buffer.data(), length + 1);
    buffer.resize(std::wcslen(buffer.c_str()));
    return wide_to_utf8(buffer);
}

void update_file_path_display() {
    if (g_app_state.use_file && !g_app_state.file_path.empty()) {
        SetWindowTextW(g_controls.filePathEdit, g_app_state.file_path.c_str());
    } else {
        SetWindowTextW(g_controls.filePathEdit, utf8_to_wide(u8"Файл не выбран").c_str());
    }
}

void clear_file_selection() {
    g_app_state.use_file = false;
    g_app_state.file_path.clear();
    g_app_state.file_data.clear();
    update_file_path_display();
}

void layout_controls(HWND hwnd) {
    RECT rc{};
    GetClientRect(hwnd, &rc);
    const int width = rc.right - rc.left;
    const int height = rc.bottom - rc.top;

    const int margin = 16;
    const int labelHeight = 20;
    const int editHeight = 24;
    const int buttonHeight = 30;
    const int labelWidth = 110;

    int y = margin;

    MoveWindow(g_controls.algorithmLabel, margin, y, labelWidth, labelHeight, TRUE);
    MoveWindow(g_controls.algorithmCombo, margin + labelWidth + 8, y - 4, std::max(100, width - (margin * 2 + labelWidth + 8)), editHeight + 8, TRUE);
    y += editHeight + 12;

    MoveWindow(g_controls.chooseFileButton, margin, y, 170, buttonHeight, TRUE);
    MoveWindow(g_controls.clearFileButton, margin + 170 + 8, y, 170, buttonHeight, TRUE);
    y += buttonHeight + 8;

    MoveWindow(g_controls.filePathEdit, margin, y, std::max(100, width - margin * 2), editHeight, TRUE);
    y += editHeight + 16;

    MoveWindow(g_controls.textLabel, margin, y, std::max(100, width - margin * 2), labelHeight, TRUE);
    y += labelHeight + 4;

    const int remainingHeight = std::max(0, height - y - margin - 12 - (buttonHeight + 12) - (labelHeight + 4) - (buttonHeight + 12));
    const int resultHeight = std::max(80, remainingHeight / 3);
    const int textHeight = std::max(80, remainingHeight - resultHeight);

    MoveWindow(g_controls.inputEdit, margin, y, std::max(100, width - margin * 2), textHeight, TRUE);
    y += textHeight + 12;

    MoveWindow(g_controls.hashButton, margin, y, 200, buttonHeight, TRUE);
    y += buttonHeight + 12;

    MoveWindow(g_controls.resultLabel, margin, y, std::max(100, width - margin * 2), labelHeight, TRUE);
    y += labelHeight + 4;

    MoveWindow(g_controls.outputEdit, margin, y, std::max(100, width - margin * 2), resultHeight, TRUE);
    y += resultHeight + 12;

    MoveWindow(g_controls.saveButton, margin, y, 240, buttonHeight, TRUE);
}

bool select_file(HWND hwnd) {
    wchar_t buffer[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    const std::wstring filter = utf8_to_wide(u8"Все файлы") + std::wstring(1, L'\0') + utf8_to_wide(u8"*.*") + std::wstring(1, L'\0');
    ofn.lpstrFilter = filter.c_str();
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = static_cast<DWORD>(std::size(buffer));
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER;

    if (!GetOpenFileNameW(&ofn)) {
        return false;
    }

    std::string data;
    if (!load_file_contents(buffer, data)) {
        MessageBoxW(hwnd, utf8_to_wide(u8"Не удалось прочитать файл.").c_str(), utf8_to_wide(u8"Ошибка").c_str(), MB_ICONERROR | MB_OK);
        return false;
    }

    g_app_state.use_file = true;
    g_app_state.file_path = buffer;
    g_app_state.file_data = std::move(data);
    update_file_path_display();
    return true;
}

void show_error(HWND hwnd, const std::wstring& message) {
    MessageBoxW(hwnd, message.c_str(), utf8_to_wide(u8"Ошибка").c_str(), MB_ICONERROR | MB_OK);
}

void compute_hash(HWND hwnd) {
    const auto& algorithms = get_algorithms();
    const LRESULT selection = SendMessageW(g_controls.algorithmCombo, CB_GETCURSEL, 0, 0);
    if (selection == CB_ERR) {
        show_error(hwnd, utf8_to_wide(u8"Выберите алгоритм хеширования."));
        return;
    }

    std::string data;
    if (g_app_state.use_file) {
        data = g_app_state.file_data;
    } else {
        data = get_edit_text_utf8(g_controls.inputEdit);
    }

    try {
        const std::string digest = algorithms[static_cast<std::size_t>(selection)].func(data);
        g_app_state.last_digest = digest;
        g_app_state.last_algorithm_index = static_cast<int>(selection);
        const std::wstring result = algorithms[static_cast<std::size_t>(selection)].title + L": " + utf8_to_wide(digest);
        SetWindowTextW(g_controls.outputEdit, result.c_str());
    } catch (const std::exception& ex) {
        show_error(hwnd, utf8_to_wide(std::string("Ошибка: ") + ex.what()));
    }
}

void save_digest(HWND hwnd) {
    if (g_app_state.last_digest.empty() || g_app_state.last_algorithm_index < 0) {
        MessageBoxW(hwnd, utf8_to_wide(u8"Сначала выполните хеширование.").c_str(),
                    utf8_to_wide(u8"Сохранение невозможно").c_str(), MB_ICONINFORMATION | MB_OK);
        return;
    }

    wchar_t buffer[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    const std::wstring save_filter = utf8_to_wide(u8"Файлы хеша (*.hash)") + std::wstring(1, L'\0') +
                                     utf8_to_wide(u8"*.hash") + std::wstring(1, L'\0') +
                                     utf8_to_wide(u8"Все файлы") + std::wstring(1, L'\0') +
                                     utf8_to_wide(u8"*.*") + std::wstring(1, L'\0');
    ofn.lpstrFilter = save_filter.c_str();
    ofn.lpstrFile = buffer;
    ofn.nMaxFile = static_cast<DWORD>(std::size(buffer));
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER;
    ofn.lpstrDefExt = L"hash";

    if (!GetSaveFileNameW(&ofn)) {
        return;
    }

    std::ofstream out(buffer, std::ios::binary);
    if (!out) {
        show_error(hwnd, utf8_to_wide(u8"Не удалось открыть файл для записи."));
        return;
    }

    const auto& algorithms = get_algorithms();
    const std::string title_utf8 = wide_to_utf8(algorithms[static_cast<std::size_t>(g_app_state.last_algorithm_index)].title);
    std::string content = title_utf8 + "\r\n" + g_app_state.last_digest + "\r\n";
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out) {
        show_error(hwnd, utf8_to_wide(u8"Не удалось сохранить файл."));
        return;
    }

    MessageBoxW(hwnd, utf8_to_wide(u8"Результат успешно сохранен.").c_str(), utf8_to_wide(u8"Готово").c_str(), MB_ICONINFORMATION | MB_OK);
}

} // namespace

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            g_ui_font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

            g_controls.algorithmLabel = CreateWindowExW(0, L"STATIC", utf8_to_wide(u8"Алгоритм:").c_str(), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_controls.algorithmCombo = CreateWindowExW(0, L"COMBOBOX", nullptr, WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1001)), nullptr, nullptr);
            g_controls.chooseFileButton = CreateWindowExW(0, L"BUTTON", utf8_to_wide(u8"Выбрать файл").c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1002)), nullptr, nullptr);
            g_controls.clearFileButton = CreateWindowExW(0, L"BUTTON", utf8_to_wide(u8"Очистить выбор").c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1003)), nullptr, nullptr);
            g_controls.filePathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1004)), nullptr, nullptr);
            g_controls.textLabel = CreateWindowExW(0, L"STATIC", utf8_to_wide(u8"Текст для хеширования:").c_str(), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_controls.inputEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1005)), nullptr, nullptr);
            g_controls.hashButton = CreateWindowExW(0, L"BUTTON", utf8_to_wide(u8"Выполнить хеширование").c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1006)), nullptr, nullptr);
            g_controls.resultLabel = CreateWindowExW(0, L"STATIC", utf8_to_wide(u8"Результат:").c_str(), WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
            g_controls.outputEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr, WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1007)), nullptr, nullptr);
            g_controls.saveButton = CreateWindowExW(0, L"BUTTON", utf8_to_wide(u8"Сохранить результат в файл").c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(1008)), nullptr, nullptr);

            apply_font(g_controls.algorithmLabel);
            apply_font(g_controls.algorithmCombo);
            apply_font(g_controls.chooseFileButton);
            apply_font(g_controls.clearFileButton);
            apply_font(g_controls.filePathEdit);
            apply_font(g_controls.textLabel);
            apply_font(g_controls.inputEdit);
            apply_font(g_controls.hashButton);
            apply_font(g_controls.resultLabel);
            apply_font(g_controls.outputEdit);
            apply_font(g_controls.saveButton);

            const auto& algorithms = get_algorithms();
            for (const auto& algorithm : algorithms) {
                SendMessageW(g_controls.algorithmCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(algorithm.title.c_str()));
            }
            if (!algorithms.empty()) {
                SendMessageW(g_controls.algorithmCombo, CB_SETCURSEL, 0, 0);
            }

            clear_file_selection();
            layout_controls(hwnd);
            return 0;
        }
        case WM_SIZE:
            layout_controls(hwnd);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = 720;
            info->ptMinTrackSize.y = 520;
            return 0;
        }
        case WM_COMMAND: {
            const int control_id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (notification == BN_CLICKED) {
                switch (control_id) {
                    case 1002:
                        select_file(hwnd);
                        break;
                    case 1003:
                        clear_file_selection();
                        break;
                    case 1006:
                        compute_hash(hwnd);
                        break;
                    case 1008:
                        save_digest(hwnd);
                        break;
                    default:
                        break;
                }
            }
            return 0;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    const wchar_t class_name[] = L"HashAppWindow";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = class_name;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, utf8_to_wide(u8"Не удалось зарегистрировать окно.").c_str(), utf8_to_wide(u8"Критическая ошибка").c_str(), MB_ICONERROR | MB_OK);
        return 0;
    }

    HWND hwnd = CreateWindowExW(0, class_name, utf8_to_wide(u8"Хеширование данных").c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 640, nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        MessageBoxW(nullptr, utf8_to_wide(u8"Не удалось создать главное окно.").c_str(), utf8_to_wide(u8"Критическая ошибка").c_str(), MB_ICONERROR | MB_OK);
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

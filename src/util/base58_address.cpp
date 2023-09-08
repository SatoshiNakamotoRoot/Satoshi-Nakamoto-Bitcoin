// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <util/base58_address.h>

#include <algorithm>

std::vector<char> Base58PrefixesFromVersionByte(size_t length, unsigned char version_byte)
{
    std::vector<char> base58_prefix_char_range;

    if (length) {
        static const unsigned char MIN_PAYLOAD_FILL = 0x00;
        static const unsigned char MAX_PAYLOAD_FILL = 0xFF;
        static const char ENCODED_LEADING_ZEROES = '1';

        const std::vector<unsigned char> payload_range = { MIN_PAYLOAD_FILL, MAX_PAYLOAD_FILL };
        std::vector<unsigned char> base58_prefix_min_max;

        for (const auto& payload : payload_range) {
            std::vector<unsigned char> range_test_bound(std::max(1, (int)length), payload);
            range_test_bound.at(0) = version_byte;
            base58_prefix_min_max.emplace_back(EncodeBase58(range_test_bound).at(0));
        }

        auto IsBase58Char = [&](char c) { return std::string_view(pszBase58).find_first_of(c) != std::string::npos; };

        if (base58_prefix_min_max.front() == ENCODED_LEADING_ZEROES) {
            base58_prefix_char_range.emplace_back(base58_prefix_min_max.front());
        } else if(IsBase58Char(base58_prefix_min_max.front()) && IsBase58Char(base58_prefix_min_max.back())) {
            for (int i = 1; pszBase58[i] != '\0'; i++) {
                base58_prefix_char_range.emplace_back(pszBase58[i]);
            }
            auto start_position = std::find(base58_prefix_char_range.begin(), base58_prefix_char_range.end(), base58_prefix_min_max.front());
            std::rotate(base58_prefix_char_range.begin(), start_position, base58_prefix_char_range.end());
            base58_prefix_char_range.erase(++std::find(base58_prefix_char_range.begin(), base58_prefix_char_range.end(), base58_prefix_min_max.back()), base58_prefix_char_range.end());
        }
    }

    return base58_prefix_char_range;
};

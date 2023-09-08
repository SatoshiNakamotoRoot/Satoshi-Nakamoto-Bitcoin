// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_BASE58_ADDRESS_H
#define BITCOIN_UTIL_BASE58_ADDRESS_H

#include <cstddef>
#include <vector>

/** Derives the first Base58 character prefixes for a given version byte and a length
 *
 * @param[in] length length of pre-encoded base58 data
 * @param[in] version_byte The address version byte
 * @return The possible range of base58 prefixes (eg. ['m','n'])
 * @code
 * std::vector result = Base58PrefixesFromVersionByte(31,0x05);
 * // result will be ['3']
 * @endcode
 */
std::vector<char> Base58PrefixesFromVersionByte(size_t length, unsigned char version_byte);

#endif // BITCOIN_UTIL_BASE58_ADDRESS_H

// Copyright (c) 2014-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_HMAC_SHA1_H
#define BITCOIN_CRYPTO_HMAC_SHA1_H

#include <crypto/sha1.h>

#include <stdint.h>
#include <stdlib.h>

/** A hasher class for HMAC-SHA-1. */
class CHMAC_SHA1
{
private:
    CSHA1 outer;
    CSHA1 inner;

public:
    static const size_t OUTPUT_SIZE = 20;

    CHMAC_SHA1(const unsigned char* key, size_t keylen);
    CHMAC_SHA1& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // BITCOIN_CRYPTO_HMAC_SHA1_H

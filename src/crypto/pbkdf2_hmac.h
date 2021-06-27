// Copyright (c) 2021 John "ComputerCraftr" Studnicka
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PBKDF2_HMAC_H
#define BITCOIN_CRYPTO_PBKDF2_HMAC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void pbkdf2_hmac_sha256(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output);

void pbkdf2_hmac_sha512(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output);

void pbkdf2_hmac_sha1(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output);

void pbkdf2_hmac_ripemd160(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output);

void pbkdf2_hmac_sha256_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output);

void pbkdf2_hmac_sha512_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output);

void pbkdf2_hmac_sha1_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output);

void pbkdf2_hmac_ripemd160_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output);

int pbkdf2_hmac_sha256_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash);

int pbkdf2_hmac_sha512_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash);

int pbkdf2_hmac_sha1_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash);

int pbkdf2_hmac_ripemd160_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash);

#ifdef __cplusplus
}
#endif

#endif // BITCOIN_CRYPTO_PBKDF2_HMAC_H

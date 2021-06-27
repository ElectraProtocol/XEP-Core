// Copyright (c) 2021 John "ComputerCraftr" Studnicka
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/pbkdf2_hmac.h>

#include <crypto/common.h>
#include <crypto/hmac_ripemd160.h>
#include <crypto/hmac_sha256.h>
#include <crypto/hmac_sha512.h>
#include <crypto/hmac_sha1.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XOR_BUF(buf, data, x) \
    buf[x] ^= data[x]

#define XOR_20(buf, data) \
    XOR_BUF(buf, data, 0); \
    XOR_BUF(buf, data, 1); \
    XOR_BUF(buf, data, 2); \
    XOR_BUF(buf, data, 3); \
    XOR_BUF(buf, data, 4); \
    XOR_BUF(buf, data, 5); \
    XOR_BUF(buf, data, 6); \
    XOR_BUF(buf, data, 7); \
    XOR_BUF(buf, data, 8); \
    XOR_BUF(buf, data, 9); \
    XOR_BUF(buf, data, 10); \
    XOR_BUF(buf, data, 11); \
    XOR_BUF(buf, data, 12); \
    XOR_BUF(buf, data, 13); \
    XOR_BUF(buf, data, 14); \
    XOR_BUF(buf, data, 15); \
    XOR_BUF(buf, data, 16); \
    XOR_BUF(buf, data, 17); \
    XOR_BUF(buf, data, 18); \
    XOR_BUF(buf, data, 19)

#define XOR_32(buf, data) \
    XOR_20(buf, data); \
    XOR_BUF(buf, data, 20); \
    XOR_BUF(buf, data, 21); \
    XOR_BUF(buf, data, 22); \
    XOR_BUF(buf, data, 23); \
    XOR_BUF(buf, data, 24); \
    XOR_BUF(buf, data, 25); \
    XOR_BUF(buf, data, 26); \
    XOR_BUF(buf, data, 27); \
    XOR_BUF(buf, data, 28); \
    XOR_BUF(buf, data, 29); \
    XOR_BUF(buf, data, 30); \
    XOR_BUF(buf, data, 31)

#define XOR_64(buf, data) \
    XOR_32(buf, data); \
    XOR_BUF(buf, data, 32); \
    XOR_BUF(buf, data, 33); \
    XOR_BUF(buf, data, 34); \
    XOR_BUF(buf, data, 35); \
    XOR_BUF(buf, data, 36); \
    XOR_BUF(buf, data, 37); \
    XOR_BUF(buf, data, 38); \
    XOR_BUF(buf, data, 39); \
    XOR_BUF(buf, data, 40); \
    XOR_BUF(buf, data, 41); \
    XOR_BUF(buf, data, 42); \
    XOR_BUF(buf, data, 43); \
    XOR_BUF(buf, data, 44); \
    XOR_BUF(buf, data, 45); \
    XOR_BUF(buf, data, 46); \
    XOR_BUF(buf, data, 47); \
    XOR_BUF(buf, data, 48); \
    XOR_BUF(buf, data, 49); \
    XOR_BUF(buf, data, 50); \
    XOR_BUF(buf, data, 51); \
    XOR_BUF(buf, data, 52); \
    XOR_BUF(buf, data, 53); \
    XOR_BUF(buf, data, 54); \
    XOR_BUF(buf, data, 55); \
    XOR_BUF(buf, data, 56); \
    XOR_BUF(buf, data, 57); \
    XOR_BUF(buf, data, 58); \
    XOR_BUF(buf, data, 59); \
    XOR_BUF(buf, data, 60); \
    XOR_BUF(buf, data, 61); \
    XOR_BUF(buf, data, 62); \
    XOR_BUF(buf, data, 63)

void pbkdf2_hmac_sha256(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || key_length < 1 || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    uint32_t block_count = 0;
    size_t added_length;

    while (key_length > 0) {
        WriteBE32(iteration_salt, ++block_count);

        CHMAC_SHA256(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
        memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

        for (uint32_t i = 1; i < iteration_count; i++) {
            CHMAC_SHA256(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

            //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
                //xor_buffer[j] ^= last_hash[j];
            //}

            XOR_32(xor_buffer, last_hash);
        }

        added_length = key_length < CHMAC_SHA256::OUTPUT_SIZE ? key_length : CHMAC_SHA256::OUTPUT_SIZE;
        memcpy(output, xor_buffer, added_length);
        output += added_length;
        key_length -= added_length;
    }
}

void pbkdf2_hmac_sha512(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || key_length < 1 || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    uint32_t block_count = 0;
    size_t added_length;

    while (key_length > 0) {
        WriteBE32(iteration_salt, ++block_count);

        CHMAC_SHA512(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
        memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

        for (uint32_t i = 1; i < iteration_count; i++) {
            CHMAC_SHA512(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

            //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
                //xor_buffer[j] ^= last_hash[j];
            //}

            XOR_64(xor_buffer, last_hash);
        }

        added_length = key_length < CHMAC_SHA512::OUTPUT_SIZE ? key_length : CHMAC_SHA512::OUTPUT_SIZE;
        memcpy(output, xor_buffer, added_length);
        output += added_length;
        key_length -= added_length;
    }
}

void pbkdf2_hmac_sha1(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || key_length < 1 || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    uint32_t block_count = 0;
    size_t added_length;

    while (key_length > 0) {
        WriteBE32(iteration_salt, ++block_count);

        CHMAC_SHA1(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
        memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

        for (uint32_t i = 1; i < iteration_count; i++) {
            CHMAC_SHA1(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

            //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
                //xor_buffer[j] ^= last_hash[j];
            //}

            XOR_20(xor_buffer, last_hash);
        }

        added_length = key_length < CHMAC_SHA1::OUTPUT_SIZE ? key_length : CHMAC_SHA1::OUTPUT_SIZE;
        memcpy(output, xor_buffer, added_length);
        output += added_length;
        key_length -= added_length;
    }
}

void pbkdf2_hmac_ripemd160(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const unsigned int iteration_count,
                unsigned int key_length,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || key_length < 1 || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    uint32_t block_count = 0;
    size_t added_length;

    while (key_length > 0) {
        WriteBE32(iteration_salt, ++block_count);

        CHMAC_RIPEMD160(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
        memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

        for (uint32_t i = 1; i < iteration_count; i++) {
            CHMAC_RIPEMD160(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

            //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
                //xor_buffer[j] ^= last_hash[j];
            //}

            XOR_20(xor_buffer, last_hash);
        }

        added_length = key_length < CHMAC_RIPEMD160::OUTPUT_SIZE ? key_length : CHMAC_RIPEMD160::OUTPUT_SIZE;
        memcpy(output, xor_buffer, added_length);
        output += added_length;
        key_length -= added_length;
    }
}

void pbkdf2_hmac_sha256_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA256(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        CHMAC_SHA256(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_32(xor_buffer, last_hash);
    }

    memcpy(output, xor_buffer, CHMAC_SHA256::OUTPUT_SIZE);
}

void pbkdf2_hmac_sha512_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA512(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        CHMAC_SHA512(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_64(xor_buffer, last_hash);
    }

    memcpy(output, xor_buffer, CHMAC_SHA512::OUTPUT_SIZE);
}

void pbkdf2_hmac_sha1_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA1(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        CHMAC_SHA1(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_20(xor_buffer, last_hash);
    }

    memcpy(output, xor_buffer, CHMAC_SHA1::OUTPUT_SIZE);
}

void pbkdf2_hmac_ripemd160_time(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                unsigned char* output)
{
    if (password == NULL || salt == NULL || output == NULL) {
        return;
    }

    uint8_t xor_buffer[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_RIPEMD160(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        CHMAC_RIPEMD160(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_20(xor_buffer, last_hash);
    }

    memcpy(output, xor_buffer, CHMAC_RIPEMD160::OUTPUT_SIZE);
}

int pbkdf2_hmac_sha256_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash)
{
    if (password == NULL || salt == NULL || hash == NULL) {
        return 0;
    }

    uint8_t xor_buffer[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA256(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        if (memcmp(hash, xor_buffer, CHMAC_SHA256::OUTPUT_SIZE) == 0) {
            return 1;
        }

        CHMAC_SHA256(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_32(xor_buffer, last_hash);
    }

    return 0;
}

int pbkdf2_hmac_sha512_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash)
{
    if (password == NULL || salt == NULL || hash == NULL) {
        return 0;
    }

    uint8_t xor_buffer[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA512::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA512(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        if (memcmp(hash, xor_buffer, CHMAC_SHA512::OUTPUT_SIZE) == 0) {
            return 1;
        }

        CHMAC_SHA512(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_64(xor_buffer, last_hash);
    }

    return 0;
}

int pbkdf2_hmac_sha1_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash)
{
    if (password == NULL || salt == NULL || hash == NULL) {
        return 0;
    }

    uint8_t xor_buffer[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_SHA1::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_SHA1(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        if (memcmp(hash, xor_buffer, CHMAC_SHA1::OUTPUT_SIZE) == 0) {
            return 1;
        }

        CHMAC_SHA1(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_20(xor_buffer, last_hash);
    }

    return 0;
}

int pbkdf2_hmac_ripemd160_time_check(const unsigned char* password,
                const unsigned int password_length,
                const unsigned char* salt,
                const unsigned int salt_length,
                const int64_t seconds_to_hash,
                const unsigned char* hash)
{
    if (password == NULL || salt == NULL || hash == NULL) {
        return 0;
    }

    uint8_t xor_buffer[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t last_hash[CHMAC_RIPEMD160::OUTPUT_SIZE];
    uint8_t iteration_salt[4];
    int64_t time_end = time(NULL) + seconds_to_hash;

    WriteBE32(iteration_salt, 1);

    CHMAC_RIPEMD160(password, password_length).Write(salt, salt_length).Write(iteration_salt, sizeof(iteration_salt)).Finalize(last_hash);
    memcpy(xor_buffer, last_hash, sizeof(xor_buffer));

    while (time(NULL) <= time_end) {
        if (memcmp(hash, xor_buffer, CHMAC_RIPEMD160::OUTPUT_SIZE) == 0) {
            return 1;
        }

        CHMAC_RIPEMD160(password, password_length).Write(last_hash, sizeof(last_hash)).Finalize(last_hash);

        //for (uint32_t j = 0; j < sizeof(xor_buffer); j++) {
            //xor_buffer[j] ^= last_hash[j];
        //}

        XOR_20(xor_buffer, last_hash);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

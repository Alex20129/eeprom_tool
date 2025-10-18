#include "crypto.h"
#include <string.h>

#define DELTA 0x9E3779B9

static const uint8_t KEY_LARGE[4][16] = {
    "ilijnaiaayuxnixo",
    "tQ\xed|{\x5c\xd8r\x17O\xe0y\n\x15\xe4\xf5",
    "uohzoahzuhidkgna",
    "uileynimdpfnangr"
};

static const uint32_t KEY_SMALL[4] = {0xBABEFACE, 0xFEEDCAFE, 0xDEADBEEF, 0xABCD55AA};

static uint32_t MX(uint32_t sum, uint32_t y, uint32_t z, uint32_t p, uint32_t e, const uint32_t *k) {
    return ((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
}

static void XXTEA_encode(uint32_t *v, int n, const uint32_t *k) {
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    rounds = 6 + 52/n;
    sum = 0;
    z = v[n-1];
    do {
        sum += DELTA;
        e = (sum >> 2) & 3;
        for (p=0; p<n-1; p++) {
            y = v[p+1];
            z = v[p] += MX(sum, y, z, p, e, k);
        }
        y = v[0];
        z = v[n-1] += MX(sum, y, z, p, e, k);
    } while (--rounds);
}

static void XXTEA_decode(uint32_t *v, int n, const uint32_t *k) {
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    rounds = 6 + 52/n;
    sum = rounds*DELTA;
    y = v[0];
    do {
        e = (sum >> 2) & 3;
        for (p=n-1; p>0; p--) {
            z = v[p-1];
            y = v[p] -= MX(sum, y, z, p, e, k);
        }
        z = v[n-1];
        y = v[0] -= MX(sum, y, z, p, e, k);
        sum -= DELTA;
    } while (--rounds);
}

void EncodeData(uint8_t *data, size_t length, uint8_t algorithm_version, uint8_t key_index) {
    if (algorithm_version == 1) {  // XXTEA
        XXTEA_encode((uint32_t*)data, length/4, (uint32_t*)KEY_LARGE[key_index]);
    } else if (algorithm_version == 2) {  // Simple XOR
        uint32_t key = KEY_SMALL[key_index];
        for (size_t i = 0; i < length; i += 4) {
            *(uint32_t*)(data + i) ^= key;
        }
    }
}

void DecodeData(uint8_t *data, size_t length, uint8_t algorithm_version, uint8_t key_index) {
    if (algorithm_version == 1) {  // XXTEA
        XXTEA_decode((uint32_t*)data, length/4, (uint32_t*)KEY_LARGE[key_index]);
    } else if (algorithm_version == 2) {  // Simple XOR
        EncodeData(data, length, algorithm_version, key_index);  // XOR is symmetric
    }
}

uint8_t CalculateCRC(const uint8_t *data, size_t bits) {
    int parity1 = 1, parity2 = 1, parity3 = 1, parity4 = 1, parity5, parity6;
    unsigned char currentParity = 1;

    for (size_t i = 0; i < bits; i++) {
        if (data[i / 8] & (1 << (7 - (i % 8)))) {
            currentParity ^= 1;
        }

        parity5 = currentParity;
        parity6 = parity2 ^ currentParity;

        if (i == bits - 1) {
            break;
        }

        parity2 = parity1;
        currentParity = parity4;
        parity4 = parity3;
        parity1 = parity5;
        parity3 = parity6;
    }

    int result = 0;
    if (parity4) result |= 16;
    if (parity3) result |= 8;
    if (parity6) result |= 4;
    if (parity1) result |= 2;
    if (parity5) result |= 1;

    return (uint8_t)result;
}

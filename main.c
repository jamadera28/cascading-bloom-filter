#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <assert.h>
#include <string.h>

#define FILTER_SIZE ((1<<20)/(sizeof(uint32_t)*8))
// 2^20 bit array, organized as an array of 32-bit ints (4 bytes * 8 bits each)

#define NUM_CERTS (1<<15)
#define DATA_LEN 32
#define print(test) printf("%s\n", test ? "revoked" : "valid")

struct cert_t
{
    size_t len;
    unsigned char data[32];
    unsigned char hash[SHA_DIGEST_LENGTH];
};

void get_offset(uint32_t idx, uint32_t *row, uint32_t *bit)
{
    *row = idx / (sizeof(uint32_t)*8);
    *bit = idx % (sizeof(uint32_t)*8);
}

void get_hash_idx(int i, uint32_t *idx, unsigned char *hash)
{
    // select 20 bits from the hash, depending on which i iteration we are on:
    if (i % 2 == 0)
        // ... we split at the MSB -4
        *idx = ((hash[i+2] & 0xF) << 16) | (hash[i+1] << 8) | (hash[i]);
    else
        // ... else we split at LSB +4
        *idx = (hash[i+2] << 12) | (hash[i+1] << 4) |((hash[i] & 0xF0) >> 4);
}

int add_to_filter(unsigned char *hash, uint32_t filter[])
{
    int i = 0;
    int num_chunks = 5;
    while (num_chunks > 0)
    {
        uint32_t idx = 0;
        uint32_t row = 0;
        uint32_t bit = 0;

        get_hash_idx(i, &idx, hash);
        get_offset(idx, &row, &bit);

        filter[row] |= (1u << bit);
        /*
        printf("setting filter row=%u, bit=%u to 1, the row now looks like:\n",row, bit);
        for (int q = 32-1; q >= 0; q--)
            putchar( ((filter[row] >> q) & 1) ? '1' : '0');
        putchar('\n');
        for (int q = 32-1; q >= 0; q--)
            putchar( (((1u << bit) >> q) & 1) ? '1' : '0');
        putchar('\n');
        */
        i+=2;
        num_chunks--;
    }
    return 0;
}

int is_cert_revoked(unsigned char *hash, uint32_t *filters[])
{

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        printf("%02x ", hash[i]);
    putchar('\n');

    int i = 0;
    int num_chunks = 5;
    int count_l0 = 0, count_l1 = 0, count_l2 =0;
    while (num_chunks > 0)
    {
        uint32_t idx = 0;
        uint32_t row = 0;
        uint32_t bit = 0;

        get_hash_idx(i, &idx, hash);
        get_offset(idx, &row, &bit);

        uint32_t f0 = filters[0][row] & (1u<<bit);
        uint32_t f1 = filters[1][row] & (1u<<bit);
        uint32_t f2 = filters[2][row] & (1u<<bit);

        printf("f[0][%02i][%02i] = %u\nf[1][%02i][%02i] = %u\nf[2][%02i][%02i] = %u\n",
            row, bit, f0 ? 1 : 0, row, bit, f1 ? 1 : 0, row, bit, f2 ? 1 : 0);
        if (f0 == 0)
            return 0;
        if (f1 == 0)
            return 1;

        count_l0 += (f0 ? 1 : 0);
        count_l1 += (f1 ? 1 : 0);
        count_l2 += (f2 ? 1 : 0);

        i += 2;
        num_chunks--;
    }
    if (count_l1 == 0)
        return 0;
    else if (count_l2 == 0)
        return 0;
    return 1;
}

int main(int argc, char *argv[])
{

    assert(FILTER_SIZE >= NUM_CERTS);
    // our 3 sample filters, 2 meant to be revoked, 1 valid
    uint32_t revoked1[FILTER_SIZE] = {0};
    uint32_t    valid[FILTER_SIZE] = {0};
    uint32_t revoked2[FILTER_SIZE] = {0};

    printf("Size of uint32_t: %lu\n", sizeof(uint32_t));
    printf("FILTER_SIZE: %lu\n", FILTER_SIZE);

    struct cert_t valid_certs[NUM_CERTS];
    struct cert_t revoked_certs[NUM_CERTS];

    memset(valid_certs, 0, (sizeof(struct cert_t)));
    memset(revoked_certs, 0, (sizeof(struct cert_t)));

    uint32_t *filters[3];

    filters[0] = revoked1;
    filters[1] = valid;
    filters[2] = revoked2;

    for (int i = 0, j = 0, k = 0; i < NUM_CERTS; i++)
    {
        unsigned char rand_data[DATA_LEN];
        arc4random_buf(rand_data, sizeof rand_data);
        struct cert_t rand_cert;
        rand_cert.len = DATA_LEN;
        strncpy((char *)rand_cert.data, (char *)rand_data, rand_cert.len);
        SHA1(rand_cert.data, rand_cert.len, rand_cert.hash);

        if (i % 4 == 0)
        {
            add_to_filter(rand_cert.hash, revoked1);
            add_to_filter(rand_cert.hash, revoked2);
            strncpy((char *)revoked_certs[j].data, (char *)rand_cert.data, DATA_LEN);
            strncpy((char *)revoked_certs[j].hash, (char *)rand_cert.hash, SHA_DIGEST_LENGTH);
            revoked_certs[j].len = rand_cert.len;
            j++;
            //assert (is_cert_revoked(rand_cert.data, rand_cert.len, filters) == 1);
        }
        else
        {
            add_to_filter(rand_cert.hash, valid);
            strncpy((char *)valid_certs[k].data, (char *)rand_cert.data, DATA_LEN);
            strncpy((char *)valid_certs[k].hash, (char *)rand_cert.hash, SHA_DIGEST_LENGTH);
            valid_certs[k].len = rand_cert.len;
            k++;
            //assert (is_cert_revoked(rand_cert.data, rand_cert.len, filters) == 0);
        }
    }

    for (int i = 0; i < 5; i++)
    {
        print(is_cert_revoked(valid_certs[i].hash, filters));
        print(is_cert_revoked(revoked_certs[i].hash, filters));
        putchar('\n');
    }

}

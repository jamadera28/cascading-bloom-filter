#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <assert.h>
#include <string.h>

#define FILTER_SIZE ((1<<20)/sizeof(uint32_t))
#define NUM_CERTS (1<<10)
#define print(test) printf("%s\n", test ? "revoked" : "valid")

void get_offset(uint32_t idx, uint32_t *row, uint32_t *bit)
{
    *row = idx / (sizeof(uint32_t)*8);
    *bit = idx % (sizeof(uint32_t)*8);
}

void get_hash_idx(int i, uint32_t *idx, unsigned char *hash)
{
    if (i % 2 == 1)
        // if split, get the other half (4 bits) and then 16 bits (20 total)
        *idx = ((hash[i] & 0xF0 )>> 4) + hash[i+1] + hash[i+2];
    else
        // get 16 bits and then half of the next byte (20 total bits)
        *idx = hash[i] + hash[i+1] + (hash[i+2] & 0xF);
}

int add_to_filter(unsigned char *cert, size_t len, uint32_t filter[])
{
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1( (unsigned char *) cert, len, hash);
    int i = 0;
    int thumbprint = 5;
    while (thumbprint > 0)
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

        i += 2;
        thumbprint--;
    }
    return 0;
}

int is_cert_revoked(unsigned char *cert, size_t len, uint32_t *filters[])
{
    unsigned char hash[SHA_DIGEST_LENGTH];

    SHA1( (unsigned char *) cert, len, hash);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        printf("%02x ", hash[i]);
    putchar('\n');

    int i = 0;
    int thumbprint = 5;
    int count_l0 = 0, count_l1 = 0, count_l2 =0;
    while (thumbprint > 0)
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
        thumbprint--;
    }
    if (count_l1 == 0)
        return 0;
    else if (count_l2 == 0)
        return 0;
    return 1;
}

int main(int argc, char *argv[])
{
    uint32_t revoked1[FILTER_SIZE] = {0};
    uint32_t revoked2[FILTER_SIZE] = {0};
    uint32_t valid[FILTER_SIZE] = {0};
    uint32_t *filters[3] = {revoked1, valid, revoked2};

    int count = 0;
    for (int i = 0; i < FILTER_SIZE; i++){
        count += 4;
    }
    printf("size = %i\n",count);

    struct cert_t
    {
        size_t len;
        unsigned char data[32];
    };

    struct cert_t valid_certs[NUM_CERTS];
    struct cert_t revoked_certs[NUM_CERTS];

    for (int i = 0, j = 0, k = 0; i < NUM_CERTS/4; i++)
    {
        unsigned char rand_data[32];
        arc4random_buf(rand_data, sizeof rand_data);
        struct cert_t rand_cert;
        strncpy((char *)rand_cert.data, (char *)rand_data, 32);
        rand_cert.len = 32;

        if (i % 4 == 0)
        {
            add_to_filter(rand_cert.data, rand_cert.len, revoked1);
            add_to_filter(rand_cert.data, rand_cert.len, revoked2);
            strncpy((char *)revoked_certs[j].data, (char *)rand_cert.data, 32);
            revoked_certs[j].len = rand_cert.len;
            j++;
            //assert (is_cert_revoked(rand_cert.data, rand_cert.len, filters) == 1);
        }
        else
        {
            add_to_filter(rand_cert.data, rand_cert.len, valid);
            //assert (is_cert_revoked(rand_cert.data, rand_cert.len, filters) == 0);
            strncpy((char *)valid_certs[k].data, (char *)rand_cert.data, 32);
            valid_certs[k].len = rand_cert.len;
            k++;
        }
    }
    for (int i = 0; i < 5; i++)
    {
        print(is_cert_revoked(valid_certs[i].data, valid_certs[i].len, filters));
        print(is_cert_revoked(revoked_certs[i].data, revoked_certs[i].len, filters));
    }

}

# cascading-bloom-filter
I heard about the concept of Cascading Bloom Filters in use for checking whether an SSL certificate is valid or revoked, so I wanted to make a small proof of concept program to perform the filter on some fake data.

## Installation
Please build with the OpenSSL library for use of the `#include <openssl/sha.h>` library.

To compile:

```
gcc -o filter main.c -lcrypto
```

This may not work on some Macs due to weird issues linking the OpenSSL library, despite being on the system normally and/or with Homebrew. If this happens, please append the `include` directory of OpenSSL installed from Homebrew to your `CPATH` environment variable, and append the `lib` directory of OpenSSL installed from Homebrew to your `LIBRARY_PATH` evnironment variable.

## Explanation

This approach creates a 2<sup>20</sup> bit array to use as a filter. We then create three of these filters:


1. if a bit is set in the first filter, then _that certificate_<sup>*</sup> should be considered revoked.
2. if a bit is set in the second filter, then _that certificate_<sup>*</sup> should be considered valid.
3. if a bit is set in the third filter, then _that certificate_<sup>*</sup> should be considered revoked.


<sup>*</sup> We decide which certificate corresponds to which bits in the filters by taking a `SHA1()` hash of the certificate---which here is just 32 bytes of randomly generated data---and getting the least significant 20 bits of the hash.
Using those 20 bits as index into each filter, we set the bit at that position if the certificate is marked for revocation in the first and third filters, and only set the bit in the second filter if it is a valid certificate.
For this demonstration, when adding certificates to the filters, we assume every iteration which is divisible by 4 generated a certficiate marked for revocation, and all other generated certificates are valid.


The filters are organized as `sizeof(uint32_t)*8` (a.k.a. 32 bit) elements of an array, and are indexed accordingly as if each bit of the 32-bit integers are an element of the 2^20 bit array using the `get_offset` function. The true array of `uint32_t` has 32,768 items as a result. This yields: 32,768 elements * (4 bytes * 8 bits/byte) == 2<sup>20</sup>.


### Caveats and Solutions to Them
We expect that setting a single bit in each of the filters using only the least significant 20 bits of the hashes will collide across the filters as the number of certificates added increases.
So, we not only set the bit(s) in the filter(s) which are indexed at the bottom 20 bits of the hash, but successfully the next most significant 20 bits of the hash---5 times total.


This way, when we test the certificates to see if they are valid or revoked, we start by checking all 3 filters in the first index (least signficant 20 bits of the hash). If the top-most revoked filter has a zero in that position, then there is zero chance of a false negative, and thus the certificate is valid.
If the bit 1 in the first revoked filter, and the valid filter has a 0, then there is no false positive, the certificate has to be invalid. These are the two base cases which guarantee a valid/revoked certificate, respectively.


But in any other case, a false positive may be possible. If the first filter's bit is 1 (meaning possibly revoked), and the second filter's bit is 1 (meaning possibly valid), then to resolve the conflict, we test the third filter.
If the third filter has a 1, then the filter is likely to be revoked. However, to be sure, we test the base case conditions again on the next successive chunk of the hash (i.e. 20 + 20 least significant bits) in the same way, and repeat if needed until none of the base cases are met or else we exhaust all 5 20-bit chunks.


### Bugs
I believe the purpose of the 3rd Bloom filter is to catch any missing revocation bits which were possible collisions in the first filter. However, my implementation right now just sets the two filters (`revoked1` level 1, and `revoked2` level 3) to be the exact same bits set. Future changes will clarify the true implementation.

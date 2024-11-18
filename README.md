# cascading-bloom-filter
I heard about the concept of Cascading Bloom Filters in use for checking whether an SSL certificate is valid or revoked, so I wanted to make a small proof of concept program to perform the filter on some fake data.

## Installation
Please build with the OpenSSL library for use of the `#include <openssl/sha.h>` library.

To compile:

```
gcc -o filter main.c -lcrypto
```

This may not work on some Macs due to weird issues linking the OpenSSL library, despite being on the system normally and/or with Homebrew.

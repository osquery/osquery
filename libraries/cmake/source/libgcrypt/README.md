# libgcrypt

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

You will need `libgpg-error` installed. Back up into the `libgpg-error` director, follow the README and add `--prefix=/home/ubuntu/libgpg-error-prefix` followed by a `make && make install`.

Generated with the following commands:

```sh
export CC=gcc

./autogen.sh
./configure --enable-static --disable-doc --disable-asm --disable-optimization --disable-sse41-support --disable-pclmul-support --disable-drng-support --disable-avx2-support --disable-avx-support --with-libgpg-error-prefix=/home/ubuntu/libgpg-error-prefix
```

You should see something similar to:

```text
        Libgcrypt v1.8.1 has been configured as follows:

        Platform:                  GNU/Linux (x86_64-pc-linux-gnu)
        Hardware detection module: hwf-x86
        Enabled cipher algorithms: arcfour blowfish cast5 des aes twofish
                                   serpent rfc2268 seed camellia idea salsa20
                                   gost28147 chacha20
        Enabled digest algorithms: crc gostr3411-94 md4 md5 rmd160 sha1
                                   sha256 sha512 sha3 tiger whirlpool stribog
                                   blake2
        Enabled kdf algorithms:    s2k pkdf2 scrypt
        Enabled pubkey algorithms: dsa elgamal rsa ecc
        Random number generator:   default
        Try using jitter entropy:  yes
        Using linux capabilities:  no
        Try using Padlock crypto:  yes
        Try using AES-NI crypto:   yes
        Try using Intel PCLMUL:    no
        Try using Intel SSE4.1:    no
        Try using DRNG (RDRAND):   no
        Try using Intel AVX:       no
        Try using Intel AVX2:      no
        Try using ARM NEON:        n/a
        Try using ARMv8 crypto:    n/a
```

Then copy

```sh
# Copy MPI sources
for source in mpih-add1.c mpih-lshift.c mpih-mul1.c mpih-mul2.c mpih-mul3.c mpih-rshift.c mpih-sub1.c mod-source-info.h mpi-asm-defs.h; \
 do cp ./mpi/${source} ../generated/ARCH/mpi/${source}; \
done
# Copy remaining headers
cp config.h ../config/ARCH
cp src/gcrypt.h ../generated/ARCH/src
```

Then build and copy cipher artifacts

```sh
(cd cipher && make)
cp cipher/gost-sb.h ../generated/ARCH/cipher
```

Finally, remove the following detections from the `config.h`:

- `HAVE_GCC_INLINE_ASM_AVX`
- `HAVE_GCC_INLINE_ASM_AVX2`
- `ENABLE_JENT_SUPPORT`

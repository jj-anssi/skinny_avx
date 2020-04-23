/*
Implementation of Skinny64/192 with AVX2.

This code verifies the test vectors for Skinny and can
also be used to run benchmarks.
*/
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include "Skinny64192AVX2.h"
#include "timing.h"

#define NUM_TIMINGS 2000

extern void unpack_and_store_message(unsigned char *out, u256 x[16]);
extern void pack_message(u256 x[16], const unsigned char *in);

//Skinny encryption using 64 blocks
#include "skinny64.c"

int crypto_stream_skinny64192ecb_avx2(
    unsigned char *out,
    unsigned char *in,
    unsigned long long inlen,
    const unsigned char *k
    ) 
{
    int i, j;
    u256 rk[NROUNDS][8];
    u256 x[16];
    u256 key;

    if (!inlen) return 0;

    key_schedule(k, rk);

    while(inlen >= 512){
        pack_message(x, in);
        encrypt_64blocks(x, rk);
        unpack_and_store_message(out, x);

        inlen -= 512;
        in += 512;
        out += 512;
    }

    return 0;
}

void check_testvector() {
    unsigned char *in,*out;
    unsigned long long inlen;

    int i;

    //Encrypt the test vector
    unsigned char plaintext[8] = {0x53,0x0c,0x61,0xd3,0x5e,0x86,0x63,0xc3};
    unsigned char k[24] = {
        0xed,0x00,0xc8,0x5b,0x12,0x0d,0x68,0x61,
        0x87,0x53,0xe2,0x4b,0xfd,0x90,0x8f,0x60,
        0xb2,0xdb,0xb4,0x1b,0x42,0x2d,0xfc,0xd0
    };
    unsigned ciphertext[8] = {0xdd,0x2c,0xf1,0xa8,0xf3,0x30,0x30,0x3c};

    //Generate 64 blocks of plaintext
    inlen=512;
    in = malloc(512);
    out = malloc(512);

    for(i = 0; i < 64; i++) {
        memcpy(in + 8*i, &plaintext, 8);
    }

    //Generate the output stream
    crypto_stream_skinny64192ecb_avx2(out,in,inlen,k);

    //Validate outputstream
    for(i = 0; i < 512; i++) {
        if(out[i] != ciphertext[i % 8]) {
            printf("ERROR: Outputstream does not match test vector at position %i!\n", i);
        }
    } 

    free(out);
    free(in);
}

int cmp_dbl(const void *x, const void *y) {
    double xx = *(double*)x, yy = *(double*)y;
    if (xx < yy) return -1;
    if (xx > yy) return 1;
    return 0;
}

int main() {
    check_testvector();
    //return 1;
    
    //Benchmark Skinny
    unsigned char *in;
    unsigned char *out;
    unsigned char *k;
    unsigned long long inlen;
    u64 timer = 0;
    double timings[NUM_TIMINGS];

    int i;
    int j;

    srand(0);
    inlen = 512 * NUM_TIMINGS;
    in = malloc(inlen);
    out = malloc(inlen);
    k = malloc(16);

    inlen = 512 * NUM_TIMINGS;

    for(i = -100; i < NUM_TIMINGS; i++) {
        //Get random input
        for(j = 0; j < inlen; j++)  in[j] = rand() & 0xff;
        for(j = 0; j < 16; j++)     k[j]  = rand() & 0xff;

        timer = start_rdtsc();
        crypto_stream_skinny64192ecb_avx2(out,in,inlen,k);
        timer = end_rdtsc() - timer;

        if(i >= 0 && i < NUM_TIMINGS) {
            timings[i] = ((double)timer) / inlen;
        }
    }

    //Get Median
    qsort(timings, NUM_TIMINGS, sizeof(double), cmp_dbl);
    printf("SKINNY-64/192: %f cycles per byte\n", timings[NUM_TIMINGS / 2]);

    free(k);
    free(out);
    free(in);
}

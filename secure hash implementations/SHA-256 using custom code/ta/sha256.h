#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stddef.h>
#include <stdint.h> // Use standard integer types

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA-256 result is 32 bytes long

/**************************** DATA TYPES ****************************/
typedef uint8_t  BYTE;             // 8-bit byte
typedef uint32_t WORD;             // 32-bit word, change to uint64_t for SHA-512
typedef uint64_t QWORD;            // 64-bit word

typedef struct {
	BYTE data[64];
	WORD datalen;
	QWORD bitlen;
	WORD state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#endif // SHA256_H

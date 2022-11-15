#include <stdint.h>
#include <stdio.h>

typedef enum {EDES, DES} Algorithm;

typedef struct {
    uint8_t *result;
    size_t length; 
} ENCRYPTION_RESULT;

extern ENCRYPTION_RESULT *encrypt(uint8_t *in, size_t in_sz);
extern ENCRYPTION_RESULT *decrypt(uint8_t *in, size_t in_sz);
extern void CAENC_CTX_new(Algorithm algo, uint8_t *key);
extern void CAENC_CTX_cleanup();

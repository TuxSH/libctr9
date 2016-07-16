/* original version by megazig */
#include <ctr9/aes.h>

//FIXME some things make assumptions about alignemnts!

void setup_aeskeyX(uint8_t keyslot, void* keyx)
{
    uint32_t * _keyx = (uint32_t*)keyx;
    *REG_AESKEYCNT = (*REG_AESKEYCNT >> 6 << 6) | keyslot | 0x80;
    if (keyslot > 3) {
        *REG_AESKEYXFIFO = _keyx[0];
        *REG_AESKEYXFIFO = _keyx[1];
        *REG_AESKEYXFIFO = _keyx[2];
        *REG_AESKEYXFIFO = _keyx[3];
    } else {
        uint32_t old_aescnt = *REG_AESCNT;
        volatile uint32_t* reg_aeskeyx = REG_AESKEY0123 + (((0x30u * keyslot) + 0x10u)/4u);
        *REG_AESCNT = (*REG_AESCNT & ~(AES_CNT_INPUT_ENDIAN | AES_CNT_INPUT_ORDER));
        for (uint32_t i = 0; i < 4u; i++)
            reg_aeskeyx[i] = _keyx[i];
        *REG_AESCNT = old_aescnt;
    }
}

void setup_aeskeyY(uint8_t keyslot, void* keyy)
{
    uint32_t * _keyy = (uint32_t*)keyy;
    *REG_AESKEYCNT = (*REG_AESKEYCNT >> 6 << 6) | keyslot | 0x80;
    if (keyslot > 3) {
        *REG_AESKEYYFIFO = _keyy[0];
        *REG_AESKEYYFIFO = _keyy[1];
        *REG_AESKEYYFIFO = _keyy[2];
        *REG_AESKEYYFIFO = _keyy[3];
    } else {
        uint32_t old_aescnt = *REG_AESCNT;
        volatile uint32_t* reg_aeskeyy = REG_AESKEY0123 + (((0x30u * keyslot) + 0x20u)/4u);
        *REG_AESCNT = (*REG_AESCNT & ~(AES_CNT_INPUT_ENDIAN | AES_CNT_INPUT_ORDER));
        for (uint32_t i = 0; i < 4u; i++)
            reg_aeskeyy[i] = _keyy[i];
        *REG_AESCNT = old_aescnt;
    }
}

void setup_aeskey(uint8_t keyslot, void* key)
{
    uint32_t * _key = (uint32_t*)key;
    *REG_AESKEYCNT = (*REG_AESKEYCNT >> 6 << 6) | keyslot | 0x80;
    if (keyslot > 3) {
        *REG_AESKEYFIFO = _key[0];
        *REG_AESKEYFIFO = _key[1];
        *REG_AESKEYFIFO = _key[2];
        *REG_AESKEYFIFO = _key[3];
    } else {
        uint32_t old_aescnt = *REG_AESCNT;
        volatile uint32_t* reg_aeskey = REG_AESKEY0123 + ((0x30u * keyslot)/4u);
        *REG_AESCNT = (*REG_AESCNT & ~(AES_CNT_INPUT_ENDIAN | AES_CNT_INPUT_ORDER));
        for (uint32_t i = 0; i < 4u; i++)
            reg_aeskey[i] = _key[i];
        *REG_AESCNT = old_aescnt;
    }
}

void use_aeskey(uint32_t keyno)
{
    if (keyno > 0x3F)
        return;
    *REG_AESKEYSEL = keyno;
    *REG_AESCNT    = *REG_AESCNT | 0x04000000; /* mystery bit */
}

void set_ctr(void* iv)
{
    uint32_t * _iv = (uint32_t*)iv;
    *REG_AESCNT = (*REG_AESCNT) | AES_CNT_INPUT_ENDIAN | AES_CNT_INPUT_ORDER;
    *(REG_AESCTR + 0) = _iv[3];
    *(REG_AESCTR + 1) = _iv[2];
    *(REG_AESCTR + 2) = _iv[1];
    *(REG_AESCTR + 3) = _iv[0];
}

void add_ctr(void* ctr, uint32_t carry)
{
    uint32_t counter[4];
    uint8_t *outctr = (uint8_t *) ctr;
    uint32_t sum;
    int32_t i;

    for(i = 0; i < 4; i++) {
        counter[i] = ((uint32_t)outctr[i*4+0]<<24) | ((uint32_t)outctr[i*4+1]<<16) | ((uint32_t)outctr[i*4+2]<<8) | ((uint32_t)outctr[i*4+3]<<0);
    }

    for(i=3; i>=0; i--)
    {
        sum = counter[i] + carry;
        if (sum < counter[i]) {
            carry = 1;
        }
        else {
            carry = 0;
        }
        counter[i] = sum;
    }

    for(i=0; i<4; i++)
    {
        outctr[i*4+0] = counter[i]>>24;
        outctr[i*4+1] = counter[i]>>16;
        outctr[i*4+2] = counter[i]>>8;
        outctr[i*4+3] = counter[i]>>0;
    }
}

void aes_decrypt(void* inbuf, void* outbuf, size_t blocks, uint32_t mode)
{
    uint32_t in  = (uint32_t)inbuf;
    uint32_t out = (uint32_t)outbuf;
    size_t block_nb;
    while (blocks != 0)
    {
        block_nb = (blocks >= 0xFFFF) ? 0xFFFF : blocks;
        *REG_AESCNT = 0;
        *REG_AESBLKCNT = block_nb << 16;
        *REG_AESCNT = mode |
                      AES_CNT_START |
                      AES_CNT_FLUSH_READ |
                      AES_CNT_FLUSH_WRITE;
        aes_fifos((void*)in, (void*)out, block_nb);
        in  += block_nb * AES_BLOCK_SIZE;
        out += block_nb * AES_BLOCK_SIZE;
        blocks -= block_nb;
    }
}

void aes_fifos(void* inbuf, void* outbuf, size_t blocks)
{
    uint32_t in  = (uint32_t)inbuf;
    if (!in) return;

    uint32_t out = (uint32_t)outbuf;
    size_t curblock = 0;
    while (curblock != blocks)
    {
        while (aescnt_checkwrite());

        size_t ii = 0;
        for (ii = in; ii != in + AES_BLOCK_SIZE; ii += 4)
        {
            uint32_t data = ((uint8_t*)ii)[0];
            data |= (uint32_t)((uint8_t*)ii)[1] << 8;
            data |= (uint32_t)((uint8_t*)ii)[2] << 16;
            data |= (uint32_t)((uint8_t*)ii)[3] << 24;
            set_aeswrfifo(data);
        }
        if (out)
        {
            while (aescnt_checkread()) ;
            for (ii = out; ii != out + AES_BLOCK_SIZE; ii += 4)
            {
                uint32_t data = read_aesrdfifo();
                ((uint8_t*)ii)[0] = data;
                ((uint8_t*)ii)[1] = data >> 8;
                ((uint8_t*)ii)[2] = data >> 16;
                ((uint8_t*)ii)[3] = data >> 24;
            }
        }
        curblock++;
    }
}

void set_aeswrfifo(uint32_t value)
{
    *REG_AESWRFIFO = value;
}

uint32_t read_aesrdfifo(void)
{
    return *REG_AESRDFIFO;
}

uint32_t aes_getwritecount()
{
    return *REG_AESCNT & 0x1F;
}

uint32_t aes_getreadcount()
{
    return (*REG_AESCNT >> 5) & 0x1F;
}

uint32_t aescnt_checkwrite()
{
    size_t ret = aes_getwritecount();
    return (ret > 0xF);
}

uint32_t aescnt_checkread()
{
    size_t ret = aes_getreadcount();
    return (ret <= 3);
}


static inline void aes128_processBlock(uint8_t* dst, uint8_t* src)
{
    uint8_t zeroes[16] = {0};
    set_ctr(zeroes);
    aes_decrypt(src, dst, 1, AES_CBC_ENCRYPT_MODE);
}

static inline void shiftBlockLeftBy1(uint8_t buf[16])
{
    int finalXOR = (buf[0] & 0x80) != 0;
    for(uint32_t i = 0; i < 15; i++)
        buf[i] = (buf[i] << 1) | (buf[i + 1] >> 7);

    buf[15] <<= 1;
    if(finalXOR)
        buf[15] ^= 0x87;
}

void cmac(void* result, void* data, size_t size)
{
    uint8_t* in = (uint8_t*) data;
    uint8_t vec[16] = {0};

    for(uint32_t i = 0; i < size / 16; i++)
    {
        for(uint32_t j = 0; j < 16; j++)
            vec[j] ^= *in++;

        aes128_processBlock(vec, vec);
    }

    // Last block
    uint32_t remaining = size % 16;
    uint8_t vec2[16] = {0};
    
    for(uint32_t i = 0; i < remaining; i++)
        vec[i] ^= *in++;
    
    aes128_processBlock(vec2, vec2);
    shiftBlockLeftBy1(vec2);

    if(remaining != 0)
    {
        vec[remaining] ^= 0x80;
        shiftBlockLeftBy1(vec2);
    }

    for(uint32_t i = 0; i < 16; i++)
        vec2[i] ^= vec[i];

    aes128_processBlock((void*) result, vec2);
}
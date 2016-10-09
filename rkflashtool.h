#define PUT32LE(x, y) \
    do { \
        (x)[0] = ((y)>> 0) & 0xff; \
        (x)[1] = ((y)>> 8) & 0xff; \
        (x)[2] = ((y)>>16) & 0xff; \
        (x)[3] = ((y)>>24) & 0xff; \
    } while (0)
#define GET32LE(p) (p)[0] + ((p)[1] << 8) + ((p)[2] << 16) + ((p)[3] << 24)

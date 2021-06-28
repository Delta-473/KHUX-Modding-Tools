#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "helper_endian.h"
#include "lodepng.h"
#include "export_image.h"

 int make_bmp(uint8_t* bmpbuf, int bmpbuf_len, int x, int y, uint8_t* imgbuf, int imgbuf_len) {

    if (imgbuf_len + 0x36 > bmpbuf_len) {
        printf("bmp too big: size %x vs max %x\n", imgbuf_len, bmpbuf_len);
        return 0;
    }

    int pos = 0;
    bmpbuf[pos++] = 0x42;
    bmpbuf[pos++] = 0x4d;
    for (int i = 0; i < 8; i++)
        bmpbuf[pos++] = 0x00;
    put_u32le(bmpbuf + 2, imgbuf_len + 0x36);

    bmpbuf[pos++] = 0x36;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x28;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;

    bmpbuf[pos++] = (x >> 0) & 0xFF;
    bmpbuf[pos++] = (x >> 8) & 0xFF;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = (y >> 0) & 0xFF;
    bmpbuf[pos++] = (y >> 8) & 0xFF;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x00;

    bmpbuf[pos++] = 0x01;
    bmpbuf[pos++] = 0x00;
    bmpbuf[pos++] = 0x20;
    for (int i = 0; i < 0x19; i++)
        bmpbuf[pos++] = 0x00;

    /* BMP expects BGRA with pre-multiplied alpha, lossless but it's a lot bigger */
    for (int i = 0; i < imgbuf_len; i += 4) {
        uint8_t r = imgbuf[i + 0];
        uint8_t g = imgbuf[i + 1];
        uint8_t b = imgbuf[i + 2];
        imgbuf[i + 0] = b;
        imgbuf[i + 1] = g;
        imgbuf[i + 2] = r;
    }

    //todo incorrect alpha settings in header
    //todo must reorder data

    memcpy(&bmpbuf[pos], imgbuf, imgbuf_len);

    return 0x36 + imgbuf_len;
}

 int make_png(uint8_t* pngbuf, int pngbuf_len, int x, int y, uint8_t* imgbuf, int imgbuf_len) {

    unsigned char* tmpbuf = NULL;
    size_t tmpbuf_len;

    /* PNG expects RBGA without pre-multiplied alpha, not lossless but not very noticeable */
    for (int i = 0; i < imgbuf_len; i += 4) {
        if (imgbuf[i + 3] > 0) {
            imgbuf[i + 0] = (float)imgbuf[i + 0] / ((float)imgbuf[i + 3] / 255.0f);
            imgbuf[i + 1] = (float)imgbuf[i + 1] / ((float)imgbuf[i + 3] / 255.0f);
            imgbuf[i + 2] = (float)imgbuf[i + 2] / ((float)imgbuf[i + 3] / 255.0f);
        }
    }

    unsigned error = lodepng_encode32(&tmpbuf, &tmpbuf_len, imgbuf, x, y);
    if (error) {
        printf("png conversion error %u: %s\n", error, lodepng_error_text(error));
        free(tmpbuf);
        return 0;
    }

    if (tmpbuf_len > pngbuf_len) {
        printf("png too big: size %x vs max %x\n", tmpbuf_len, pngbuf_len);
        free(tmpbuf);
        return 0;
    }

    memcpy(pngbuf, tmpbuf, tmpbuf_len);
    free(tmpbuf);

    return tmpbuf_len;
}

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "decode_btf.h"
#include "miniz.h"

// TODO: not cleaned up, not portable, too much alloc, whatevs
int decode_btf(uint8_t* src_arg, int src_size, int* p_x1, int* p_y1, uint8_t** p_dstbuf, int* p_dstbuf_len, uint8_t* p_outflag1, uint8_t* p_outflag2, int flag_half, int* p_x2, int* p_y2) {
    const static uint8_t btf_id[] = {
        0x89,0x42,0x54,0x46,0,0
    };

    unsigned int v11; // r8
    uint8_t* imgbuf; // r9
    int flags2; // r10
    unsigned int img_x2; // r11
    int tmp_multi; // lr
    uint8_t* src; // r4
    int p_y1tmp1; // r5
    int p_x1tmp1; // r6
    unsigned int result; // r0
    int img_y1; // r9
    int img_x1; // r5
    unsigned int* datbuf_len_p; // r6
    unsigned int datbuf_len; // r4
    uint8_t* datbuf; // r8
    unsigned int imgbuf_tmplen; // r0
    unsigned int p_x1tmp1_; // r2
    int v27; // r3
    int v28; // r1
    int v29; // r0
    uint8_t* v30; // r1
    unsigned int v31; // r3
    int v32; // r2
    uint8_t* v33; // r5
    uint8_t* v34; // r4
    int v35; // r3
    int v36; // t1
    uint8_t* imgptr; // r6
    int dstpos; // r1
    int ctr1; // r8
    uint8_t* dstptr; // r1
    int ctr3; // r3
    int ctr1b; // r4
    uint8_t ctr1_test; // zf
    unsigned int val; // r5
    unsigned int val_shr4; // r2
    int ctr2; // r3
    char outflag2_test; // r0
    uint8_t* dstptr_; // r4
    unsigned int v49; // r0
    int v50; // r3
    int v51; // r0
    uint8_t* v52; // r5
    uint8_t* v53; // r2
    int v54; // r1
    int v55; // t1
    unsigned int v56; // r12
    unsigned int v57; // r3
    int v58; // r5
    int v59; // r4
    unsigned int v60; // r3
    unsigned int v61; // r6
    int v62; // r8
    uint8_t* v63; // r5
    unsigned int v64; // r6
    int v65; // r3
    int v66; // r4
    int v67; // r12
    int v68; // r8
    unsigned int v69; // lr
    uint8_t* v70; // r8
    uint8_t* v71; // r4
    uint8_t* v72; // r2
    int v73; // t1
    unsigned int v74; // r4
    uint8_t* v75; // r2
    int v76; // t1
    int v77; // r6
    uint8_t* imgptr_; // r8
    int v79; // r2
    int v80; // r12
    int v81; // r5
    int v82; // r8
    unsigned int v83; // r0
    int* v84; // r6
    uint8_t* v85; // r3
    int* v86; // r1
    int v87; // t1
    uint8_t* v88; // r3
    unsigned int v89; // r0
    int v90; // t1
    int v91; // [sp+4h] [bp-5Ch]
    int v92; // [sp+Ch] [bp-54h]
    unsigned int v93; // [sp+10h] [bp-50h]
    int v94; // [sp+10h] [bp-50h]
    int dstbuf_len; // [sp+14h] [bp-4Ch]
    int img_y0; // [sp+18h] [bp-48h]
    int tmp_x1; // [sp+1Ch] [bp-44h]
    int tmp_y1; // [sp+20h] [bp-40h]
    int16_t flags1; // [sp+24h] [bp-3Ch]
    int* p_x1tmp2; // [sp+28h] [bp-38h]
    int* p_y1tmp2; // [sp+2Ch] [bp-34h]
    int v102; // [sp+30h] [bp-30h]
    unsigned int img_y3; // [sp+34h] [bp-2Ch]
    unsigned int img_y3a; // [sp+34h] [bp-2Ch]
    int img_y3b; // [sp+34h] [bp-2Ch]
    uint8_t* dstbuf; // [sp+38h] [bp-28h]
    int flags2_val; // [sp+3Ch] [bp-24h]
    unsigned int img_x3; // [sp+40h] [bp-20h]
    unsigned int img_x3a; // [sp+40h] [bp-20h]
    unsigned int img_x3b; // [sp+40h] [bp-20h]
    int img_x0; // [sp+44h] [bp-1Ch]
    int img_y2; // [sp+48h] [bp-18h]
    long unsigned int imgbuf_len; // [sp+4Ch] [bp-14h]
    unsigned int stack_guard = 0xDEADBEEF; // [sp+50h] [bp-10h]

    src = src_arg;
    p_y1tmp1 = (int)p_y1;
    p_x1tmp1 = (int)p_x1;
    if (src_size >= 4 && !memcmp(btf_id, src_arg, 6u))
    {
        p_x1tmp2 = (int*)p_x1tmp1;
        p_y1tmp2 = (int*)p_y1tmp1;
        (flags2) = *((int16_t*)src + 8);
        img_x2 = *((uint16_t*)src + 15);
        img_y1 = *((uint16_t*)src + 12);
        img_x1 = *((uint16_t*)src + 11);
        img_y2 = *((uint16_t*)src + 16);
        flags1 = *((int16_t*)src + 3);
        if (flags2 & 1)
        {
            datbuf_len_p = (unsigned int*)(src + 36);
            img_y3 = *((uint16_t*)src + 14);
            img_x3 = *((uint16_t*)src + 13);
            flags2_val = *((uint16_t*)src + 17);
        }
        else
        {
            img_y3 = *((uint16_t*)src + 14);
            img_x3 = *((uint16_t*)src + 13);
            datbuf_len_p = (unsigned int*)(src + 34);
            flags2_val = 0;
        }

        datbuf_len = *datbuf_len_p;
        datbuf = malloc(*datbuf_len_p);
        memcpy(datbuf, datbuf_len_p + 1, datbuf_len);

        if (flag_half)
        {
            img_y0 = (unsigned int)(img_y1 + 1) >> 1;
            img_x0 = (unsigned int)(img_x1 + 1) >> 1;
        }
        else
        {
            img_y0 = img_y1;
            img_x0 = img_x1;
        }

        dstbuf_len = 4 * img_x1 * img_y1;
        dstbuf = malloc(4 * img_x1 * img_y1);
        memset(dstbuf, 0, 4 * img_x1 * img_y1);

        if (flags2 & 8)
        {
            if (flags2_val)
            {
                tmp_x1 = img_x1;
                tmp_y1 = img_y1;
                imgbuf_tmplen = img_y2 * img_x2 + 4 * flags2_val;
            }
            else
            {
                tmp_x1 = img_x1;
                tmp_y1 = img_y1;
                imgbuf_tmplen = 4 * img_x2 * img_y2;
            }
            imgbuf_len = imgbuf_tmplen;
            imgbuf = malloc(imgbuf_tmplen);
            uncompress(imgbuf, &imgbuf_len, datbuf, datbuf_len);
            free(datbuf);
        }
        else
        {
            tmp_x1 = img_x1;
            tmp_y1 = img_y1;
            imgbuf = datbuf;
            imgbuf_len = datbuf_len;
        }

        p_y1tmp1 = img_x3;
        p_x1tmp1_ = img_y3;

        v11 = img_x3 >> flag_half;
        tmp_multi = flag_half;
        result = img_y3 >> flag_half;
        if (flags2 & 0x10)
        {
            if (img_y2)
            {
                tmp_multi = img_x2 & 1;
                flags2 = 0;
                imgptr = &imgbuf[4 * flags2_val];
                dstpos = img_x0 * (uint16_t)result + (uint16_t)v11;
                ctr1 = 1;
                dstptr = &dstbuf[4 * dstpos];
                do
                {
                    if (img_x2)
                    {
                        ctr3 = 0;
                        ctr1b = ctr1;
                        do
                        {
                            ctr1_test = (ctr1b & 1) == 0;
                            val = *imgptr;
                            ctr1b ^= 1u;
                            val_shr4 = val >> 4;
                            if (!ctr1_test)
                                val_shr4 = val & 0xF;
                            *(int32_t*)&dstptr[4 * ctr3] = *(int32_t*)&imgbuf[4 * val_shr4];
                            if (ctr1_test)
                                ++imgptr;
                            ++ctr3;
                        } while (img_x2 != ctr3);
                        ctr2 = img_x2 & 1;
                        if (img_x2 & 1)
                            ctr2 = 1;
                        ctr1 ^= ctr2;
                    }
                    dstptr += 4 * img_x0;
                    ++flags2;
                } while (flags2 != img_y2);
            }
        }
        else
        {
            if (!flags2_val)
                goto LABEL_45;
            v27 = (uint16_t)result;
            v28 = img_x0 * (uint16_t)result;
            v29 = (int)&imgbuf[4 * flags2_val];
            v30 = &dstbuf[4 * (v28 + (uint16_t)v11)];
            if (flags2 & 0x400)
            {
                v56 = (unsigned int)(img_y2 + 1) >> 1;
                v57 = (img_x2 + 1) >> 1;
                if (flag_half == 1)
                {
                    if (v56)
                    {
                        v58 = 0;
                        do
                        {
                            if (v57)
                            {
                                v59 = 0;
                                do
                                {
                                    *(int32_t*)&v30[4 * v59] = *(int32_t*)&imgbuf[4 * *(uint8_t*)(v29 + v59)];
                                    ++v59;
                                } while (v57 != v59);
                            }
                            ++v58;
                            v30 += 4 * img_x0;
                            v29 += v57;
                        } while (v58 != v56);
                    }
                }
                else if (v57 && v56)
                {
                    flags2 = v29 + (img_x2 >> 1);
                    img_x3a = (unsigned int)&v30[8 * (img_x2 >> 1)];
                    v67 = 0;
                    v93 = img_x2 >> 1;
                    v68 = (int)&v30[4 * (img_x0 + 2 * (img_x2 >> 1))];
                    v91 = 8 * img_x0;
                    v92 = img_x2 & 1;
                    do
                    {
                        img_x2 = v29 + v67 * v57;
                        v69 = v93;
                        img_y3a = v68;
                        v102 = 2 * v67;
                        v70 = (uint8_t*)(v29 + v67 * v57);
                        v71 = (uint8_t*)(v29 + v67 * v57);
                        v72 = &v30[4 * img_x0 * 2 * v67];
                        if (v93)
                        {
                            do
                            {
                                v73 = *v71++;
                                --v69;
                                *(int32_t*)v72 = *(int32_t*)&imgbuf[4 * v73];
                                *((int32_t*)v72 + 1) = *(int32_t*)&imgbuf[4 * v73];
                                v72 += 8;
                            } while (v69);
                            v72 = (uint8_t*)img_x3a;
                            v70 = (uint8_t*)flags2;
                        }
                        tmp_multi = (unsigned int)(img_y2 + 1) >> 1;
                        if (v92)
                            *(int32_t*)v72 = *(int32_t*)&imgbuf[4 * *v70];
                        if ((v102 | 1) < img_y2)
                        {
                            v74 = v93;
                            v75 = &v30[4 * (v102 | 1) * img_x0];
                            if (v93)
                            {
                                do
                                {
                                    v76 = *(uint8_t*)img_x2++;
                                    --v74;
                                    v77 = *(int32_t*)&imgbuf[4 * v76];
                                    *(int32_t*)v75 = *(int32_t*)&imgbuf[4 * v76];
                                    *((int32_t*)v75 + 1) = v77;
                                    v75 += 8;
                                } while (v74);
                                v75 = (uint8_t*)img_y3a;
                                img_x2 = flags2;
                            }
                            if (v92)
                                *(int32_t*)v75 = *(int32_t*)&imgbuf[4 * *(uint8_t*)img_x2];
                        }
                        ++v67;
                        flags2 += v57;
                        v68 = img_y3a + v91;
                        img_x3a += v91;
                    } while (v67 != (unsigned int)(img_y2 + 1) >> 1);
                }
            }
            else if (flag_half)
            {
                v31 = ((img_y2 + img_y3) >> 1) - v27;
                if ((int16_t)v31)
                {
                    flags2 = (uint16_t)v31;
                    tmp_multi = (uint16_t)(((img_x3 + img_x2) >> 1) - v11);
                    v32 = 0;
                    do
                    {
                        if ((uint16_t)((img_x3 + img_x2) >> 1) != (int16_t)v11)
                        {
                            v33 = (uint8_t*)(v29 + v32 * (uint16_t)(2 * img_x2));
                            v34 = &v30[4 * img_x0 * v32];
                            v35 = (uint16_t)(((img_x3 + img_x2) >> 1) - v11);
                            do
                            {
                                v36 = *v33;
                                v33 += 2;
                                --v35;
                                *(int32_t*)v34 = *(int32_t*)&imgbuf[4 * v36];
                                v34 += 4;
                            } while (v35);
                        }
                        ++v32;
                    } while (v32 != flags2);
                }
            }
            else if (img_y2)
            {
                v65 = 0;
                do
                {
                    if (img_x2)
                    {
                        v66 = 0;
                        do
                        {
                            *(int32_t*)&v30[4 * v66] = *(int32_t*)&imgbuf[4 * *(uint8_t*)(v29 + v66)];
                            ++v66;
                        } while (img_x2 != v66);
                    }
                    v30 += 4 * img_x0;
                    v29 += img_x2;
                    ++v65;
                } while (v65 != img_y2);
            }
        }
        goto LABEL_40;
    }
    for (result = 0; ; result = 1)
    {
        p_x1tmp1_ = stack_guard;
        if ( /*_stack_chk_guard ==*/ stack_guard == 0xDEADBEEF) /* ??? */
            break;
    LABEL_45:
        result = (uint16_t)result;
        dstptr_ = &dstbuf[4 * ((uint16_t)result * img_x0 + (uint16_t)v11)];
        if (flags2 & 0x400)
        {
            v60 = (unsigned int)(img_y2 + 1) >> 1;
            v61 = (img_x2 + 1) >> 1;
            if (tmp_multi == 1)
            {
                if (v60)
                {
                    img_x2 = (2 * img_x2 + 2) & 0x3FFFC;
                    v62 = 4 * v61;
                    v63 = imgbuf;
                    flags2 = 4 * img_x0;
                    do
                    {
                        v64 = v60;
                        memcpy(dstptr_, v63, v62);
                        v63 += img_x2;
                        dstptr_ += flags2;
                        v60 = v64 - 1;
                    } while (v64 != 1);
                }
            }
            else if (v61 && v60)
            {
                img_x3b = img_x2 >> 1;
                v79 = (int)&imgbuf[4 * (img_x2 >> 1)];
                v80 = (int)&dstptr_[8 * (img_x2 >> 1)];
                v81 = 0;
                flags2 = (int)&dstptr_[4 * (img_x0 + 2 * (img_x2 >> 1))];
                v94 = 8 * img_x0;
                img_y3b = img_x2 & 1;
                do
                {
                    v82 = 2 * v81;
                    img_x2 = v61;
                    tmp_multi = (int)&imgbuf[4 * v81 * v61];
                    v83 = img_x3b;
                    v84 = (int*)tmp_multi;
                    v85 = &dstptr_[4 * 2 * v81 * img_x0];
                    v86 = (int*)tmp_multi;
                    if (img_x3b)
                    {
                        do
                        {
                            v87 = *v86;
                            ++v86;
                            --v83;
                            *(int32_t*)v85 = v87;
                            *((int32_t*)v85 + 1) = v87;
                            v85 += 8;
                        } while (v83);
                        v85 = (uint8_t*)v80;
                        v84 = (int*)v79;
                    }
                    if (img_y3b)
                        *(int32_t*)v85 = *v84;
                    v61 = img_x2;
                    if ((v82 | 1) < img_y2)
                    {
                        v88 = &dstptr_[4 * (v82 | 1) * img_x0];
                        v89 = img_x3b;
                        if (img_x3b)
                        {
                            do
                            {
                                v90 = *(int32_t*)tmp_multi;
                                tmp_multi += 4;
                                --v89;
                                *(int32_t*)v88 = v90;
                                *((int32_t*)v88 + 1) = v90;
                                v88 += 8;
                            } while (v89);
                            v88 = (uint8_t*)flags2;
                            tmp_multi = v79;
                        }
                        if (img_y3b)
                            *(int32_t*)v88 = *(int32_t*)tmp_multi;
                    }
                    v79 += 4 * img_x2;
                    ++v81;
                    flags2 += v94;
                    v80 += v94;
                } while (v81 != (unsigned int)(img_y2 + 1) >> 1);
            }
        }
        else if (tmp_multi)
        {
            v49 = ((img_y2 + p_x1tmp1_) >> 1) - result;
            if ((int16_t)v49)
            {
                flags2 = ((img_x2 + p_y1tmp1) >> 1) - (uint16_t)v11;
                v50 = (uint16_t)v49;
                tmp_multi = (uint16_t)(((img_x2 + p_y1tmp1) >> 1) - v11);
                v51 = 0;
                do
                {
                    if ((int16_t)flags2)
                    {
                        v52 = &imgbuf[4 * v51 * (uint16_t)(2 * img_x2)];
                        v53 = &dstptr_[4 * img_x0 * v51];
                        v54 = tmp_multi;
                        do
                        {
                            v55 = *(int32_t*)v52;
                            v52 += 8;
                            --v54;
                            *(int32_t*)v53 = v55;
                            v53 += 4;
                        } while (v54);
                    }
                    ++v51;
                } while (v51 != v50);
            }
        }
        else if (img_y2)
        {
            imgptr_ = imgbuf;
            do
            {
                memcpy(dstptr_, imgptr_, 4 * img_x2);
                imgptr_ += 4 * img_x2;
                dstptr_ += 4 * img_x0;
                --img_y2;
            } while (img_y2);
        }
    LABEL_40:
        //(v11) = (int16_t)p_y2;
        p_y1tmp1 = (int)p_x2;
        free(imgbuf);
        *p_x1tmp2 = tmp_x1;
        *p_y1tmp2 = tmp_y1;
        *p_dstbuf = dstbuf;
        *p_dstbuf_len = dstbuf_len;
        *p_outflag1 = flags1 & 1;
        outflag2_test = 0;
        if (flags2_val == 1 && *(int32_t*)dstbuf < 0x1000000u)
            outflag2_test = 1;
        *p_outflag2 = outflag2_test;
        *p_x2 = img_x0;
        *p_y2 = img_y0;
    }
    return result;
}

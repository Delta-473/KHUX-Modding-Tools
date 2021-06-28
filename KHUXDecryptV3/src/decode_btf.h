#pragma once

int decode_btf(uint8_t* src_arg, int src_size, int* p_x1, int* p_y1, uint8_t** p_dstbuf, int* p_dstbuf_len, uint8_t* p_outflag1, uint8_t* p_outflag2, int flag_half, int* p_x2, int* p_y2);
#pragma once
#include <stdint.h>

static inline void put_u16be(uint8_t* buf, uint16_t v) {
    buf[0] = (uint8_t)((v >> 8u) & 0xFF);
    buf[1] = (uint8_t)(v & 0xFF);
}
static inline void put_u16le(uint8_t* buf, uint16_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)(v >> 8u);
}
static inline void put_u32be(uint8_t* buf, uint32_t v) {
    buf[0] = (uint8_t)((v >> 24u) & 0xFF);
    buf[1] = (uint8_t)((v >> 16u) & 0xFF);
    buf[2] = (uint8_t)((v >> 8u) & 0xFF);
    buf[3] = (uint8_t)(v & 0xFF);
}
static inline void put_u32le(uint8_t* buf, uint32_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8u) & 0xFF);
    buf[2] = (uint8_t)((v >> 16u) & 0xFF);
    buf[3] = (uint8_t)((v >> 24u) & 0xFF);
}

static inline uint16_t get_u16be(uint8_t* p) {
    return (uint16_t)((p[0] << 8u) | (p[1]));
}
static inline uint32_t get_u32be(uint8_t* p) {
    return (uint32_t)((p[0] << 24u) | (p[1] << 16u) | (p[2] << 8u) | (p[3]));
}
static inline uint16_t get_u16le(uint8_t* p) {
    return (uint16_t)((p[0]) | (p[1] << 8u));
}
static inline uint32_t get_u32le(uint8_t* p) {
    return (uint32_t)((p[0]) | (p[1] << 8u) | (p[2] << 16u) | (p[3] << 24u));
}
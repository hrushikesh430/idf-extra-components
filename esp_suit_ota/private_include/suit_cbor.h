/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A small reader for deterministic CBOR (RFC 8949 section 4.2.1): definite lengths only,
 * shortest integer encodings only. Everything the manifest profile needs, nothing more.
 */

#define SUIT_CBOR_UINT   0
#define SUIT_CBOR_NINT   1
#define SUIT_CBOR_BSTR   2
#define SUIT_CBOR_TSTR   3
#define SUIT_CBOR_ARRAY  4
#define SUIT_CBOR_MAP    5
#define SUIT_CBOR_TAG    6
#define SUIT_CBOR_SIMPLE 7

typedef struct {
    uint8_t major;
    uint8_t ai;          /* additional information, 0..27 */
    uint64_t val;        /* argument: integer value, length, count or tag */
    uint8_t len;         /* bytes of the head */
} suit_cbor_head_t;

/**
 * @brief Decode one item head from n available bytes.
 * @return head length, 0 when more bytes are needed, -1 when the encoding is not deterministic
 */
int suit_cbor_head(const uint8_t *p, size_t n, suit_cbor_head_t *h);

typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} suit_cbor_t;

static inline void suit_cbor_init(suit_cbor_t *c, const uint8_t *p, size_t len)
{
    c->p = p;
    c->end = p + len;
}

static inline bool suit_cbor_at_end(const suit_cbor_t *c)
{
    return c->p >= c->end;
}

esp_err_t suit_cbor_peek(const suit_cbor_t *c, suit_cbor_head_t *h);
esp_err_t suit_cbor_get_uint(suit_cbor_t *c, uint64_t *v);
esp_err_t suit_cbor_get_int(suit_cbor_t *c, int64_t *v);
esp_err_t suit_cbor_get_bstr(suit_cbor_t *c, const uint8_t **ptr, size_t *len);
esp_err_t suit_cbor_get_tstr(suit_cbor_t *c, const uint8_t **ptr, size_t *len);
esp_err_t suit_cbor_get_bool(suit_cbor_t *c, bool *v);
esp_err_t suit_cbor_get_nil(suit_cbor_t *c);
esp_err_t suit_cbor_get_array(suit_cbor_t *c, size_t *count);
esp_err_t suit_cbor_get_map(suit_cbor_t *c, size_t *count);
esp_err_t suit_cbor_get_tag(suit_cbor_t *c, uint64_t *tag);
/** @brief Skip one item, nested content included. */
esp_err_t suit_cbor_skip(suit_cbor_t *c);
/** @brief Span of the next item including its head, then advance past it. */
esp_err_t suit_cbor_get_raw(suit_cbor_t *c, const uint8_t **ptr, size_t *len);

#ifdef __cplusplus
}
#endif

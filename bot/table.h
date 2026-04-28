#pragma once

#include <stdint.h>
#include "includes.h"

struct table_value {
    char *val;
    uint16_t val_len;
#ifdef DEBUG
    BOOL locked;
#endif
};

#define TABLE_KEY_LEN (sizeof(table_keys) / sizeof(*table_keys))

#define TABLE_CNC_DOMAIN        0
#define TABLE_EXEC_SUCCESS      1
#define TABLE_ATK_VSE           3
#define TABLE_KILLER_PROC       4
#define TABLE_KILLER_EXE        5
#define TABLE_KILLER_FD         6

#define TABLE_REPORT_IP         18
#define TABLE_RELAY_1           19
#define TABLE_RELAY_2           20
#define TABLE_RELAY_3           21
#define TABLE_RELAY_4           22
#define TABLE_MAX_KEYS          23

void table_init(void);
void table_unlock_val(uint8_t);
void table_lock_val(uint8_t); 
char *table_retrieve_val(int, int *);

static void add_entry(uint8_t, char *, int);
static void toggle_obf(uint8_t);

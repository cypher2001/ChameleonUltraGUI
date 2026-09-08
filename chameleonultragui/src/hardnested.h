//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// hf mf hardnested command
//-----------------------------------------------------------------------------

#ifndef HARDNESTED_H
#define HARDNESTED_H

#include "pm3/common.h"

// Hardnested async execution state, polled from the GUI while a worker
// thread runs the attack in the background. Defined here (not in the FFI
// header) because the vendored attack files reference the stages.
typedef enum
{
    HN_STATE_IDLE = 0,
    HN_STATE_RUNNING = 1,
    HN_STATE_DONE = 2,
    HN_STATE_CANCELLED = 3,
    HN_STATE_ERROR = 4
} HardnestedState;

typedef enum
{
    HN_STAGE_INIT = 0,
    HN_STAGE_READ_NONCES = 1,
    HN_STAGE_BITFLIP = 2,
    HN_STAGE_CANDIDATES = 3,
    HN_STAGE_BRUTEFORCE = 4
} HardnestedStage;

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey,
                 bool nonce_file_read, bool nonce_file_write, bool slow, uint64_t *foundkey, char *nonces_char, uint32_t length);
void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time);

// Progress / cancel hooks for async (GUI) execution. Implemented in
// recovery.c. hardnested_progress_report() is invoked at stage transitions
// and during brute force; hardnested_cancel_requested() must be polled by
// long-running loops so a cancel can interrupt the attack.
void hardnested_progress_report(int stage, const char *activity, float progress);
int hardnested_cancel_requested(void);
#endif // HARDNESTED_H

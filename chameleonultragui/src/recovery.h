#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#if _WIN32
#define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FFI_PLUGIN_EXPORT
#endif

typedef struct
{
    uint32_t nt1;
    uint64_t ks1;
    uint64_t par;
    uint32_t nr;
    uint32_t ar;
} DarksideItem;

typedef struct
{
    uint32_t uid;
    DarksideItem *items;
    uint32_t count;
} Darkside;

typedef struct
{
    uint32_t uid;
    uint32_t dist;
    uint32_t nt0;
    uint32_t nt0_enc;
    uint32_t par0;
    uint32_t nt1;
    uint32_t nt1_enc;
    uint32_t par1;
} Nested;

typedef struct
{
    uint32_t uid;
    uint32_t key_type;
    uint32_t nt0;
    uint32_t nt0_enc;
    uint32_t nt1;
    uint32_t nt1_enc;
} StaticNested;

typedef struct
{
    uint32_t uid;
    uint32_t nt;
    uint32_t nt_enc;
    uint32_t nt_par_enc;
} StaticEncryptedNested;

typedef struct
{
    uint32_t uid;     // serial number
    uint32_t nt0;     // tag challenge first
    uint32_t nt1;     // tag challenge second
    uint32_t nr0_enc; // first encrypted reader challenge
    uint32_t ar0_enc; // first encrypted reader response
    uint32_t nr1_enc; // second encrypted reader challenge
    uint32_t ar1_enc; // second encrypted reader response
} Mfkey32;

typedef struct
{
    uint32_t uid;    // serial number
    uint32_t nt;     // tag challenge
    uint32_t nr_enc; // encrypted reader challenge
    uint32_t ar_enc; // encrypted reader response
    uint32_t at_enc; // encrypted tag response / next nt
} Mfkey64;

typedef struct
{
    char *nonces;
    uint32_t length;
} HardNested;

// Hardnested async execution state, polled from the GUI while a worker
// pthread runs the attack in the background. Stage/state values match
// HardnestedState / HardnestedStage in hardnested.h (kept as plain int32_t
// here so this FFI header stays self-contained for bindings generation).
typedef struct
{
    int32_t state;    // HardnestedState
    int32_t stage;    // HardnestedStage
    float progress;   // 0.0..1.0 during brute force, else 0.0
    uint64_t key;     // recovered key when state == HN_STATE_DONE
    char activity[96];
} HardnestedStatus;

FFI_PLUGIN_EXPORT uint64_t *darkside(Darkside *data, uint32_t *keyCount);

FFI_PLUGIN_EXPORT uint64_t *nested(Nested *data, uint32_t *keyCount);

FFI_PLUGIN_EXPORT uint64_t *static_nested(StaticNested *data, uint32_t *keyCount);

FFI_PLUGIN_EXPORT uint64_t *static_encrypted_nested(StaticEncryptedNested *data, uint32_t *keyCount);

FFI_PLUGIN_EXPORT uint64_t mfkey32(Mfkey32 *data);

FFI_PLUGIN_EXPORT uint64_t mfkey64(Mfkey64 *data);

FFI_PLUGIN_EXPORT uint64_t hardnested(HardNested *data);

// Asynchronous hardnested with progress polling and cooperative cancel.
// Start copies the nonce buffer, spawns a worker pthread and returns
// immediately. The GUI polls the scalar getters below; cancel is
// cooperative: the attack checks the flag between work items and stops as
// soon as possible, after which hardnested_async_state() reports
// HN_STATE_CANCELLED. Only one async attack may run at a time (the
// underlying pm3 code uses file-static state and is not reentrant) — start
// returns nonzero while one is running or on invalid input.
FFI_PLUGIN_EXPORT int hardnested_async_start(HardNested *data);
FFI_PLUGIN_EXPORT void hardnested_async_cancel(void);
FFI_PLUGIN_EXPORT int hardnested_async_state(void);    // HardnestedState
FFI_PLUGIN_EXPORT int hardnested_async_stage(void);    // HardnestedStage
FFI_PLUGIN_EXPORT float hardnested_async_progress(void); // 0..1 brute force, else 0
FFI_PLUGIN_EXPORT uint64_t hardnested_async_key(void); // recovered key when done
FFI_PLUGIN_EXPORT void hardnested_async_activity(char *out, int len); // current stage text

// Progress / cancel hooks called from the vendored pm3 attack code.
// Implemented in recovery.c; declared here so hardnested.c and
// hardnested_bruteforce.c can call them.
FFI_PLUGIN_EXPORT void hardnested_progress_report(int stage, const char *activity, float progress);
FFI_PLUGIN_EXPORT int hardnested_cancel_requested(void);

/* Events: everything that can happen to the core.
 *
 * The program around the core turns each outside occurrence into one gz_event_t
 * and passes it to gz_node_handle. The core answers with a list of actions
 * (action.h). It never waits and never reaches outside itself.
 *
 * Ownership: every pointer inside an event belongs to the caller and need only
 * stay valid for the duration of the call it is passed to. The core copies
 * whatever it wants to keep. */
#ifndef GAZPACHO_EVENT_H
#define GAZPACHO_EVENT_H

#include "gazpacho/types.h"

typedef enum {
    GZ_EVENT_MESSAGE_RECEIVED = 1, /* a peer sent us a message */
    GZ_EVENT_TIMER_FIRED,          /* a timer set by an earlier action is due */
    GZ_EVENT_CHAIN,                /* something happened on chain */
    GZ_EVENT_USER_COMMAND,         /* the user asked for something */
    GZ_EVENT_STORAGE_CONFIRMED     /* a save batch is safely stored */
} gz_event_kind_t;

/* Kinds of chain event. More will be added as the engines need them. */
typedef enum {
    GZ_CHAIN_SCRIPT_SPENT = 1,  /* an output paying a watched script was spent */
    GZ_CHAIN_TX_CONFIRMED,      /* a transaction reached a number of confirmations */
    GZ_CHAIN_NEW_TIP            /* the best chain has a new tip */
} gz_chain_kind_t;

typedef struct {
    gz_chain_kind_t kind;
    gz_bytes_t script;       /* SCRIPT_SPENT: the watched script */
    uint8_t txid[32];        /* SCRIPT_SPENT: the spending transaction;
                                TX_CONFIRMED: the confirmed transaction */
    uint32_t confirmations;  /* TX_CONFIRMED: how many, counting its own block */
    uint32_t height;         /* NEW_TIP: the tip's height; otherwise the height of
                                the block containing the transaction */
} gz_chain_event_t;

typedef struct {
    gz_event_kind_t kind;
    union {
        struct { uint64_t peer_id; gz_bytes_t bytes; } message; /* MESSAGE_RECEIVED */
        struct { uint64_t timer_id; } timer;                    /* TIMER_FIRED */
        gz_chain_event_t chain;                                 /* CHAIN */
        struct { gz_bytes_t bytes; } user;                      /* USER_COMMAND: opaque for now */
        struct { gz_batch_id_t batch; } storage;                /* STORAGE_CONFIRMED */
    } u;
} gz_event_t;

#endif

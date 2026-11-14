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
    GZ_EVENT_STORAGE_CONFIRMED,    /* a save batch is safely stored */
    GZ_EVENT_PEER_CONNECTED,       /* a connection to a peer is up */
    GZ_EVENT_PEER_DISCONNECTED     /* a connection to a peer is down */
} gz_event_kind_t;

/* Kinds of chain event. Every kind but NEW_TIP and BROADCAST_RESULT answers a
 * watch (action.h, WATCHES, which says when each is reported). */
typedef enum {
    GZ_CHAIN_SCRIPT_SPENT = 1,  /* retired in contract v2 (section 10): never given */
    GZ_CHAIN_TX_CONFIRMED,      /* a watched transaction has a number of confirmations */
    GZ_CHAIN_NEW_TIP,           /* the best chain has a new tip; after a reorganisation
                                   its height may be lower than the last one reported */
    GZ_CHAIN_TX_UNCONFIRMED,    /* a watched transaction reported as confirmed is no
                                   longer in the best chain */
    GZ_CHAIN_OUTPOINT_SPENT,    /* a watched outpoint is spent, by `txid` */
    GZ_CHAIN_BROADCAST_RESULT   /* advice about a BROADCAST: accepted, refused or not sent */
} gz_chain_kind_t;

/* Outcome of a broadcast (GZ_CHAIN_BROADCAST_RESULT). Advice only: never
 * stored as proof, never final; watches are the only truth (action.h). The
 * event is lost with a restart. */
typedef enum {
    GZ_BROADCAST_ACCEPTED = 1,  /* a server took it, or already had it */
    GZ_BROADCAST_REFUSED,       /* every server that answered refused it; `reason` says why */
    GZ_BROADCAST_UNREACHABLE    /* no server answered */
} gz_broadcast_outcome_t;

typedef struct {
    gz_chain_kind_t kind;
    gz_outpoint_t outpoint;  /* OUTPOINT_SPENT: the watched outpoint */
    uint8_t txid[32];        /* OUTPOINT_SPENT: the spending transaction;
                                TX_CONFIRMED, TX_UNCONFIRMED: the watched transaction;
                                BROADCAST_RESULT: the broadcast transaction's txid,
                                computed by the program from the bytes sent.
                                In the byte order the chain hashes it, not reversed
                                for display (types.h, action.h) */
    uint32_t confirmations;  /* TX_CONFIRMED, OUTPOINT_SPENT: how many, counting its own
                                block; 0 for a spender not in the best chain */
    uint32_t height;         /* NEW_TIP: the tip's height; otherwise the height of the
                                block containing the transaction, 0 if none */
    gz_broadcast_outcome_t outcome; /* BROADCAST_RESULT */
    gz_bytes_t reason;       /* BROADCAST_RESULT, REFUSED: printable ASCII, at most 127
                                bytes, the first refusing server's words */
} gz_chain_event_t;

typedef struct {
    gz_event_kind_t kind;
    union {
        /* MESSAGE_RECEIVED: a whole factory message the transport has
         * checked (envelope.h: header, direction, record table, parts put
         * back together). */
        struct { gz_link_t link; uint16_t kind; uint8_t scope[32]; gz_bytes_t records; } message;
        struct { uint64_t timer_id; } timer;                    /* TIMER_FIRED */
        gz_chain_event_t chain;                                 /* CHAIN */
        /* USER_COMMAND: a TLV stream, command.h: request_id, method, path,
         * digest, command, arguments. */
        struct { gz_bytes_t bytes; } user;
        struct { gz_batch_id_t batch; } storage;                /* STORAGE_CONFIRMED */
        /* PEER_CONNECTED, PEER_DISCONNECTED. `outbound`: 1 if we connected
         * (then key_epoch and key_index name our key, as in the CONNECT);
         * 0 if we accepted. */
        struct { gz_link_t link; int outbound; uint32_t key_epoch; uint32_t key_index; } peer;
    } u;
} gz_event_t;

#endif

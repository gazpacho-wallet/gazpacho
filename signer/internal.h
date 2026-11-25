/* The signer's state, private to signer/ (signer.c and the vectors build's
 * vectors_aux.c). Never installed, never included from outside signer/. */
#ifndef GAZPACHO_SIGNER_INTERNAL_H
#define GAZPACHO_SIGNER_INTERNAL_H

#include "gazpacho/signer.h"

#include <secp256k1_extrakeys.h>

typedef struct {
    int used;
    gz_sg_slot_t slot;
    uint8_t contribution_pub[33];
    uint8_t contribution_xonly[32];
    uint8_t factory_pub[33];
    secp256k1_keypair contribution_kp;   /* SECRET; a member's only (a host signs with its own key) */
} sg_slot_t;

struct gz_signer {
    uint32_t magic;
    gz_sg_config_t cfg;
    uint32_t net_level;
    int have_host;
    uint8_t host_pub[33];
    uint8_t host_xonly[32];
    secp256k1_keypair host_kp;           /* SECRET, held while the program runs */
    sg_slot_t slots[GZ_SG_MAX_SLOTS];
};

#endif

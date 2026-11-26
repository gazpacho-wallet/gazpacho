/* SPDX-License-Identifier: MIT */
/* The passphrase layer this build links (unlock.h): the wallet's encrypted
 * storage (store_unlock.c, gzp_wallet_unlock_api), in gazpacho and in
 * gazpacho-test alike. One wallet per process: the one main.c opened. */
#ifndef GZP_UNLOCK_IMPL_H
#define GZP_UNLOCK_IMPL_H

#include "datadir.h"
#include "unlock.h"

void gzp_unlock_impl(gzp_unlock_t *u, gzp_datadir_t *dir);

#endif

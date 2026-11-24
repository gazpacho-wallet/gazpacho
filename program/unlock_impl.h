/* SPDX-License-Identifier: MIT */
/* The passphrase layer this build links (unlock.h): the TEST-ONLY stand-in
 * in gazpacho-test (unlock_standin.c), none in the release program
 * (unlock_none.c) until encrypted storage is wired in. */
#ifndef GZP_UNLOCK_IMPL_H
#define GZP_UNLOCK_IMPL_H

#include "datadir.h"
#include "unlock.h"

void gzp_unlock_impl(gzp_unlock_t *u, gzp_datadir_t *dir);

#endif

/* A regression fixture for signer_never_ship (review A of #71): a call to the
 * vectors build reached by split token pasting, which no text check reads.
 * nm sees the undefined gz_sgv_ name all the same. Built as a test library
 * only; nothing links it. */
#include "gazpacho/signer.h"

#define NS_CAT(a, b) a##b
#define NS_PASTE(a, b) NS_CAT(a, b)

extern int NS_PASTE(gz_sg, v_sign_envelope_fixed)(void);
int ns_paste_probe(void);
int ns_paste_probe(void) { return NS_PASTE(gz_sg, v_sign_envelope_fixed)(); }

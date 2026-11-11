/* A very small test harness and the shared fixtures for ports/chain tests. */
#ifndef GZ_CHAIN_TEST_H
#define GZ_CHAIN_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/chain.h"
#include "gazpacho/chain_http.h"

typedef struct test_state {
  int tests, checks, failed;
} test_state;

#define CHECK(cond)                                                              \
  do {                                                                           \
    T->checks++;                                                                 \
    if (!(cond)) {                                                               \
      T->failed++;                                                               \
      fprintf(stderr, "  %s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                            \
  } while (0)

#define CHECK_RESULT(expr, want)                                                        \
  do {                                                                                  \
    gz_chain_result got_ = (expr);                                                      \
    T->checks++;                                                                        \
    if (got_ != (want)) {                                                               \
      T->failed++;                                                                      \
      fprintf(stderr, "  %s:%d: %s returned %s, wanted %s\n", __FILE__, __LINE__, #expr, \
              gz_chain_result_name(got_), gz_chain_result_name(want));                  \
    }                                                                                   \
  } while (0)

#define RUN(fn)                                                \
  do {                                                         \
    int before_ = T->failed;                                   \
    T->tests++;                                                \
    fn(T);                                                     \
    printf("%s %s\n", T->failed == before_ ? "ok  " : "FAIL", #fn); \
  } while (0)

#define TEST_MAIN_END(name)                                                               \
  printf("%s: %d tests, %d checks, %d failed\n", name, T->tests, T->checks, T->failed);   \
  return T->failed == 0 ? 0 : 1

/* ---- the recorded signet facts (ports/chain/tests/data/README.md) ---- */

#define TX_A "8690387a65262437580d45b77f1cb0792faff46cecb72c5ee22390e5193a6c9a" /* block 329438, position 1 */
#define TX_B "a8f29683fcf6687b0944580cca8ee91b44c7ce3fa79fddcafc3c33334e5f411f" /* block 329438, position 2 */
#define TX_SPENDER "ee18add119d09dc5b01cde93367391947495b656c30c5935cbde8374aa9d944b" /* block 329439; input 0 spends TX_A:0 */
#define TX_NONE "0000000000000000000000000000000000000000000000000000000000000001"
#define SCRIPT_A2 "0014ea6f435d306838385ae16fa43b0cebb6c2f0cdb9" /* paid by TX_A output 2, 43000 sat */
#define SCRIPT_A2_HASH "c7ecf6689f2f6ac8edddcd98b48ab7ab6283d59ccf1c692124f86ba503387cd0"
#define HASH_329437 "00000006b68515903881b6dc0f91070ac24d499369dd97f7778d8612d39108b5"
#define HASH_329438 "0000000e272942ba41a93bf06e25f0171c0efc02710e7cd58735243e712a1cf4"
#define HASH_329439 "0000000598cb99835ee5e9b03bbbf95e3627cb8ac471e664f19e02b43f8e8318"
#define TIP_HEIGHT 329439u

/* Reads a recorded file from the data directory into a malloc'd, zero-
 * terminated buffer. Aborts the test program if the file is missing. */
char *test_read_data(const char *name, size_t *len);
/* Parses a 64-character display-order hex hash; aborts on bad input. */
void test_hash(const char *hex, uint8_t out[GZ_HASH_LEN]);
/* Deterministic pseudo-random numbers for the mutation tests. */
uint64_t test_rand(uint64_t *state);

/* ---- the fake transport ---- */

#define FAKE_MAX_ROUTES 96
#define FAKE_URL_MAX 420
#define FAKE_MAX_SLEEPS 64

typedef struct fake_route {
  bool post;
  char url[FAKE_URL_MAX];
  gz_http_result result;
  long status;
  uint8_t *body;
  size_t len;
  int remaining; /* -1: answers for ever; n > 0: answers n more times */
  unsigned hits;
} fake_route;

typedef struct fake_http {
  fake_route routes[FAKE_MAX_ROUTES];
  size_t n;
  uint64_t now_ms;
  unsigned requests;   /* every request made */
  unsigned unexpected; /* requests no route matched */
  char last_url[FAKE_URL_MAX];
  uint8_t last_body[4096];
  size_t last_body_len;
  uint32_t last_timeout_ms;
  size_t last_cap;
  uint32_t sleeps[FAKE_MAX_SLEEPS];
  size_t n_sleeps;
  uint64_t starts[FAKE_MAX_SLEEPS]; /* clock value when each request began */
  bool down;                        /* every request fails to connect */
  bool overrun;                     /* break the transport contract: claim more bytes than the cap */
} fake_http;

void fake_init(fake_http *f);
void fake_free(fake_http *f);
gz_http fake_transport(fake_http *f);
/* A route that answers for ever. Replaces an earlier permanent route for the
 * same method and address. */
void fake_set(fake_http *f, bool post, const char *url, long status, const char *body);
void fake_set_bytes(fake_http *f, bool post, const char *url, long status, const void *body,
                    size_t len);
void fake_set_file(fake_http *f, const char *url, long status, const char *data_file);
/* A route that answers `times` times and is tried before permanent routes.
 * `result` other than GZ_HTTP_OK simulates a transport failure. */
void fake_once(fake_http *f, bool post, const char *url, gz_http_result result, long status,
               const char *body, int times);
unsigned fake_hits(const fake_http *f, bool post, const char *url);
/* Loads every recorded answer of an honest signet server at `base`, with the
 * tip at TIP_HEIGHT. `blockstream` selects that operator's fee answer. */
void fake_load_honest(fake_http *f, const char *base, bool blockstream);

#endif /* GZ_CHAIN_TEST_H */

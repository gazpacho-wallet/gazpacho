/* journal.c compiled with its allocations routed through the test's hook
 * (test_journal_alloc.c): only the journal's own malloc, calloc and realloc
 * are replaced, not the test's or the memfs's. free stays free. */
#define malloc gz_test_malloc
#define calloc gz_test_calloc
#define realloc gz_test_realloc
#include "../../ports/storage/journal.c"

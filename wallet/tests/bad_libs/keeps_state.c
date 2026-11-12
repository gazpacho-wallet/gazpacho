/* Negative test for check_no_io.py: a "library" with global state. */
int gzw_bad_counter;

int gzw_bad_keeps_state(void);
int gzw_bad_keeps_state(void) { return ++gzw_bad_counter; }

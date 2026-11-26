/* The exit engine, tree half (spec/exit.md 6.8). Not written yet: every
 * call refuses, so its tests fail. */
#include "gazpacho/exit_engine.h"

gz_xe_plan_err_t gz_xe_plan_member(const gz_xe_tree_in_t *in, uint32_t member, const uint8_t own_key[33],
                                   gz_xe_plan_t *out)
{
    (void)in; (void)member; (void)own_key; (void)out;
    return GZ_XE_PLAN_ARGUMENT;
}

gz_xe_plan_err_t gz_xe_plan_host(const gz_xe_tree_in_t *in, const uint8_t *owed, gz_xe_plan_t *out)
{
    (void)in; (void)owed; (void)out;
    return GZ_XE_PLAN_ARGUMENT;
}

gz_status_t gz_xe_init(gz_xe_t *x, const uint8_t scope[32], const gz_xe_port_t *port)
{
    (void)x; (void)scope; (void)port;
    return GZ_OK;
}

gz_status_t gz_xe_begin(gz_xe_t *x, const gz_xe_plan_t *plan, uint8_t reason, gz_action_list_t *out, int *refused)
{
    (void)x; (void)plan; (void)reason; (void)out; (void)refused;
    return GZ_ERR_ARGUMENT;
}

gz_status_t gz_xe_load(void *e, const gz_record_t *rec, gz_batch_id_t at)
{
    (void)e; (void)rec; (void)at;
    return GZ_ERR_ARGUMENT;
}

gz_status_t gz_xe_resume(void *e, gz_action_list_t *out, int *more)
{
    (void)e; (void)out; (void)more;
    return GZ_ERR_ARGUMENT;
}

gz_status_t gz_xe_handle(void *e, const gz_event_t *ev, gz_action_list_t *out)
{
    (void)e; (void)ev; (void)out;
    return GZ_ERR_ARGUMENT;
}

int gz_xe_step_state(const gz_xe_t *x, size_t i)
{
    (void)x; (void)i;
    return 0;
}

int gz_xe_has_ended(const gz_xe_t *x, uint8_t *how)
{
    (void)x; (void)how;
    return 0;
}

void gz_xe_anchor_child(const uint8_t txid[32], uint32_t vout, uint8_t out[GZ_XE_CHILD_LEN])
{
    (void)txid; (void)vout; (void)out;
}

int gz_xe_strip_witness(const uint8_t *tx, size_t len, uint8_t *out, size_t cap, size_t *out_len, int *had_witness)
{
    (void)tx; (void)len; (void)out; (void)cap; (void)out_len; (void)had_witness;
    return 0;
}

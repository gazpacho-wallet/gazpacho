
## Added after the M1a follow-up reviews

27. **A multi-step start that reads storage must work from a fixed view, or
    record only what it has actually done.** A start that re-reads storage
    between steps can record an action (a message as "sent") against a record
    that appeared after the step began but was never acted on. Storage may
    grow during a start (late writes from a dead program, the node's own
    saves); a start must still never claim to have done what it has not.
28. **A save made early in a start holds back every later send**, because the
    runner releases nothing outward until earlier saves are confirmed. A start
    that must both resend and record should resend everything first and save
    its records last, so the resends do not wait behind a record's
    confirmation. More generally: order a step's actions so that what must
    leave does not sit behind a save.
29. **An invariant checks the property itself, not a proxy for it.** "No
    one-time secret is reused" is checked on the secret values the engines
    actually use (exposed for the test), not on what they drew from the random
    port: a naive engine can mislabel its draw, and a careful one mixes the
    draw with other material, so the draws are the wrong thing to compare.
30. **A fault the code describes must be one the test harness can produce.**
    The runner's contract allowed storage to fail from inside the executor,
    but the simulator had no way to make it happen, so a mutation that ignored
    that path looked equivalent to correct. Every path a contract names needs
    a fault that exercises it.

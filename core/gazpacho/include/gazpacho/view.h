/* The composite node's view objects and its local-API engine (step P6a;
 * contract-v2.md section 11; composite-node.md section 10, step 9).
 *
 * The node offers no reads. It emits a NOTIFY GZ_NOTIFY_VIEW(kind) for each
 * object whenever the object changes, after the saves of the state it shows
 * (node.h rule 8), and every object again at each start (rule 7). The
 * program keeps the newest bytes per (kind, id); the API server answers
 * spec/local-api.md's calls from them. docs/notes/view-objects.md maps every
 * field of the API's answers to a record below, or says where it comes from
 * when the core does not hold it.
 *
 * Every object is a TLV stream (envelope.h): 0 id, 2 gone, 4 version
 * (command.h), then the fields below. Integers are big-endian; "ms" is Unix
 * milliseconds; a field is absent when its value is unknown or null. */
#ifndef GAZPACHO_VIEW_H
#define GAZPACHO_VIEW_H

#include "gazpacho/command.h"

/* ---- kind 1, status: one object, id "status" (local-api.md 11.1) --------- */
#define GZ_VIEW_STATUS_ID          "status"
#define GZ_VST_ROLE                6   /* u8: 0 member, 1 host (the data folder's) */
#define GZ_VST_PAUSE               8   /* u8 state (GZ_PAUSE_*), u64 since ms (0: none), u32 version */
#define GZ_VST_PAUSE_LOBBIES       10  /* the held lobbies' local ids, ASCII, comma-separated */
#define GZ_VST_SIGNING             12  /* u8 member_signing in force, u8 pending (0xff: none),
                                          u32 version of the saved setting (0: never saved),
                                          u8 host_funding in force */
#define GZ_VST_NODE_GATE           14  /* u8: 1 open, 0 closed (meaningful under when_unlocked) */
#define GZ_VST_DOING               16  /* u8 code (GZ_DOING_*), u8 role (GZ_ROLE_*), u64 since ms,
                                          then the lobby's local id (ASCII, may be empty) */
#define GZ_VST_LOBBIES             18  /* entries, each: u8 role, u8 stage, u8 doing, u64 since ms,
                                          u8 id length, the local id */
#define GZ_VST_LEFT_OUT            20  /* u16: lobbies left out at this start (no keys) */
#define GZ_VST_CONDITIONS          22  /* u32 version of the saved conditions (0: never saved), then
                                          the conditions as GZ_CMD_API_SET_CONDITIONS carries them */
#define GZ_VST_PRESET              24  /* ASCII: the saved preset; absent: custom or never saved */

#define GZ_PAUSE_OFF               0
#define GZ_PAUSE_ON                1
#define GZ_PAUSE_HELD              2   /* held_for_signing: a round with partial signatures out */

#define GZ_ROLE_NONE               0
#define GZ_ROLE_JOINED             1
#define GZ_ROLE_HOSTED             2

/* ---- kind 2, lobby: a member's lobby, id its local id (14.1) -------------- */
#define GZ_VLB_FINGERPRINT         6   /* 32: the outer digest (the scope) */
#define GZ_VLB_HOST_KEY            8   /* 33 */
#define GZ_VLB_HOST_ADDRESS        10  /* ASCII "host:port" */
#define GZ_VLB_STAGE               12  /* u8: messages.md lobby state 0..7 as the member knows it */
#define GZ_VLB_SEAT                14  /* u8: GZ_VSEAT_* */
#define GZ_VLB_READY_VERSION       16  /* u32: the values version readied for */
#define GZ_VLB_GATE                18  /* u8 kind (GZ_GATE_*), u8 state (1 open), u64 since ms,
                                          then 32 opened_for_digest when per-lobby and open */
#define GZ_VLB_LOCKED_SINCE        20  /* u64 ms: the seat is out of the count (unready reason 3) */
#define GZ_VLB_OUTER               22  /* the outer rules record, as signed (terms.md) */
#define GZ_VLB_OUTER_SIG           24  /* 64 */
#define GZ_VLB_CURRENT             26  /* the newest current values record */
#define GZ_VLB_CURRENT_SIG         28  /* 64 */
#define GZ_VLB_FROZEN              30  /* u32 version, 32 digest: the values frozen by the check */
#define GZ_VLB_FIT                 32  /* u8 class (GZ_FIT_*), u8 term (terms.md type; 0: none),
                                          u64 yours, u64 offered (the failing term's two values) */
#define GZ_VLB_OUTCOME             34  /* u8 code (GZ_OUTCOME_*), u16 reason */
#define GZ_VLB_ROUND               36  /* u8: the saved round outcome, 0, 4 Funding or 5 Active */
#define GZ_VLB_DOING               38  /* u8: GZ_DOING_* */
#define GZ_VLB_SINCE               40  /* u64 ms: when stage, seat or doing last changed */
#define GZ_VLB_PAUSED              42  /* u8 1: left or held by the pause */

/* Seat values of local-api.md 14.1 (messages.md seat states 0..7, then
 * joining). */
#define GZ_VSEAT_NONE              0
#define GZ_VSEAT_JOINED            1   /* joined_not_ready */
#define GZ_VSEAT_READY             2
#define GZ_VSEAT_CHOSEN            3
#define GZ_VSEAT_NOT_CHOSEN        4
#define GZ_VSEAT_LEFT              5
#define GZ_VSEAT_REMOVED           6
#define GZ_VSEAT_REFUSED_BY_HOST   7
#define GZ_VSEAT_JOINING           8
#define GZ_VSEAT_LOCKED            9   /* host view only (15.3) */
#define GZ_VSEAT_REFUSED           10  /* host view only: the member refused (15.3) */

#define GZ_GATE_NONE               0   /* auto */
#define GZ_GATE_NODE               1   /* when_unlocked */
#define GZ_GATE_PER_LOBBY          2   /* at_join */

#define GZ_VFIT_FITS               0
#define GZ_VFIT_FITS_NOW_ONLY      1
#define GZ_VFIT_DOES_NOT_FIT       2

/* you.outcome codes the core decides in P6a (14.1); the round outcomes
 * (signing_unfinished, abandoned, dead, started, aborted_before_signatures)
 * come with the signing engine (P4.3) and keep their numbers here. */
#define GZ_OUTCOME_NONE                 0
#define GZ_OUTCOME_REFUSED_AT_CHECK     1
#define GZ_OUTCOME_ABORTED_BEFORE_SIGS  2
#define GZ_OUTCOME_REFUSED_BY_HOST      3
#define GZ_OUTCOME_REMOVED              4
#define GZ_OUTCOME_LEFT                 5
#define GZ_OUTCOME_CANCELLED            6
#define GZ_OUTCOME_NOT_UNLOCKED_IN_TIME 7
#define GZ_OUTCOME_NOT_CHOSEN           8
#define GZ_OUTCOME_SIGNING_UNFINISHED   9
#define GZ_OUTCOME_ABANDONED            10
#define GZ_OUTCOME_DEAD                 11
#define GZ_OUTCOME_STARTED              12

/* doing.code values of local-api.md 11.2 that a lobby gives. */
#define GZ_DOING_NONE                   0
#define GZ_DOING_IN_LOBBY_NOT_READY     1
#define GZ_DOING_IN_LOBBY_NOT_COUNTED   2   /* ready, but the seat is locked */
#define GZ_DOING_IN_LOBBY_WAITING       3
#define GZ_DOING_READY_CHECK            4
#define GZ_DOING_SIGNING                5
#define GZ_DOING_AWAITING_FUNDING       6
#define GZ_DOING_JOINING                7
#define GZ_DOING_HOSTING_OPEN           8   /* host: open, gathering seats */
#define GZ_DOING_LOBBY_CANCELLED        9
#define GZ_DOING_PAUSED                 10

/* ---- kind 3, host_lobby: a hosted lobby, id its local id (15.3) ----------- */
#define GZ_VHL_FINGERPRINT         6   /* 32 */
#define GZ_VHL_STAGE               8   /* u8: messages.md lobby state */
#define GZ_VHL_OUTER               10
#define GZ_VHL_OUTER_SIG           12
#define GZ_VHL_CURRENT             14
#define GZ_VHL_CURRENT_SIG         16
#define GZ_VHL_COUNTS              18  /* u16 joined, u16 ready, u16 locked, u16 refused */
#define GZ_VHL_SEATS               20  /* entries of GZ_VHL_SEAT_LEN bytes, in order of joining:
                                          33 contribution key, u8 state (GZ_VSEAT_*), u8 flags
                                          (GZ_VHL_F_*), u16 refusal reason, u8 refusal stage
                                          (GZ_STAGE_*), u64 join order, u32 ready version,
                                          u16 min_members */
#define GZ_VHL_LISTED              22  /* u8 */
#define GZ_VHL_STANDBYS            24  /* u16 */
#define GZ_VHL_END_REASON          26  /* u16: the cancel reason, once ended */
#define GZ_VHL_ROUND               28  /* u8 started (a start was sent), u64 budget start ms */
#define GZ_VHL_DOING               30  /* u8: GZ_DOING_* */
#define GZ_VHL_SINCE               32  /* u64 ms */
#define GZ_VHL_PAUSED              34  /* u8 1: the pause holds the start rule */
#define GZ_VHL_FROZEN              36  /* u32 version, 32 digest */
#define GZ_VHL_SET_ASIDE           38  /* u64: set_aside_sat, what an early start echoes
                                          (gz_fund_set_aside_sat; absent: none can be confirmed) */

#define GZ_VHL_SEAT_LEN            52
#define GZ_VHL_F_LOCKED            0x01
#define GZ_VHL_F_REFUSED           0x02
#define GZ_VHL_F_CHOSEN            0x04
#define GZ_VHL_F_ANSWERED          0x08
#define GZ_VHL_F_CONNECTED         0x10

#define GZ_STAGE_OPEN              1   /* refusal.at_stage */
#define GZ_STAGE_READY_CHECK       2
#define GZ_STAGE_SIGNING           3

/* ---- kind 10, discovery: a query to a host, id "q_N" (local-api.md 14.2) ----
 * The lobbies it found are kind 2 objects with no seat (GZ_VSEAT_NONE), each
 * with a local id for the run (7.3) that its slot keeps if the person joins. */
#define GZ_VDQ_STATE               6   /* u8: 1 asking, 2 answered, 3 failed */
#define GZ_VDQ_HOST_KEY            8   /* 33 */
#define GZ_VDQ_ADDRESS             10  /* ASCII */
#define GZ_VDQ_ASKED               12  /* u64 ms */
#define GZ_VDQ_ENDED               14  /* u64 ms: answered or failed */
#define GZ_VDQ_FAILED              16  /* ASCII: no_answer, unreachable */
#define GZ_VDQ_LOBBIES             18  /* the lobbies' local ids, ASCII, comma-separated */
#define GZ_VLB_SEEN                44  /* u64 ms: a lobby seen in a query (no slot), the query's last answer */

/* ---- kind 7, attention: one item, id "att_" ... (11.4) -------------------- */
#define GZ_VAT_CODE                6   /* u8: GZ_ATT_* */
#define GZ_VAT_LOBBY               8   /* the lobby's local id */
#define GZ_VAT_SINCE               10  /* u64 ms */
/* 12 is not used: an item never carries the fingerprint, which 7.3 keeps
 * out of every event (review A of PR 55, M5); every lobby slot has a local id. */
#define GZ_VAT_COUNT               14  /* u16: member_refused, the refused seats */

#define GZ_ATT_UNLOCK_TO_TAKE_PART 1
#define GZ_ATT_LOBBY_LEFT_OUT      2
#define GZ_ATT_MEMBER_REFUSED      3
#define GZ_ATT_HOST_FUNDS_SHORT    4   /* 11.4: the automatic start waits for the host's funds */
#define GZ_VAT_NEED                16  /* u64: host_funds_short, what the funding needs */
#define GZ_VAT_HAVE                18  /* u64: ... what the wallet holds for it */
#define GZ_VAT_ROLE                20  /* u8: GZ_ROLE_JOINED or GZ_ROLE_HOSTED (11.4: every lobby item names its role) */

/* ---- the local-API engine (area 0x000d) --------------------------------- */
/* Commands (command.h; arguments from type 10). */
#define GZ_CMD_API_PAUSE           0x0d01  /* 12 on (u8 1 on, 0 off), 14 based_on_version (u32; required
                                              to resume: another answers 409 changed_elsewhere) */
#define GZ_CMD_API_SET_SIGNING     0x0d02  /* 12 member_signing (u8), 14 based_on_version (u32),
                                              16 confirm_member_signing (u8; required, equal to 12, for auto).
                                              The one command that sets the signing mode (W11) */
#define GZ_CMD_API_SET_CONDITIONS  0x0d03  /* 12 the conditions (LOBBY_JOIN's encoding, node.h; empty: no
                                              limits), 14 based_on_version (u32), 16 confirm_loosens (the
                                              GZ_COND_L_* codes the change loosens, u8 each, increasing;
                                              required, exactly, when it loosens any), 18 preset (ASCII,
                                              1 to 16 of a-z and _; absent: custom). PUT /api/v1/conditions */

/* What a conditions change loosens (local-api.md 13.2 `loosens`): the
 * terms.md type of the term it compares, or one of these two. */
#define GZ_COND_L_COMPARE          1   /* compare_with: whole_range to current_value */
#define GZ_COND_L_HINT             2   /* the ready hint (min_members of `ready`) lowered */
/* and GZ_TT_PROFILE (8), GZ_TT_MINIMUM (12), GZ_TT_LIFETIME (26, either bound),
 * GZ_TT_CHANNEL (30), GZ_TT_FEERATE (32), an adjustable type (64 and up). */

/* Records (journal.md 9.1; local-api.md 7.5). */
#define GZ_RECORD_PAUSE            0x000d000cu /* 2 state (u8), 4 since ms (u64), 6 held scopes (n x 32),
                                                  8 version (u32) */
#define GZ_RECORD_LOCAL_IDS        0x000d000eu /* 2 scope (32), 4 local id (ASCII) */
#define GZ_RECORD_REQUEST_ID       0x000d0014u /* 2 request_id, 4 method, 6 path, 8 digest (32),
                                                  10 status (u16), 12 the acted-on lobby's local id,
                                                  14 created ms (u64), 15 the answer's error code */
#define GZ_RECORD_SIGNING_SETTING  0x000d0024u /* 2 member_signing (u8), 4 host_funding (u8), 6 version (u32) */
#define GZ_RECORD_CONDITIONS       0x000d0008u /* 2 the conditions (GZ_CMD_API_SET_CONDITIONS's 12; may be
                                                  empty), 4 version (u32), 6 preset (ASCII; absent: custom),
                                                  8 the version of the last save that tightened anything
                                                  (u32, at most 4; absent: 4) */

#define GZ_LOCAL_ID_MAX            64
/* Request ids kept (7.4: until the object ended and 30 days passed).
 * - A lobby's: each lobby keeps at most GZ_API_LOBBY_SHARE, and a call that
 *   protects funds (leave) has GZ_API_LOBBY_RESERVE more. A call over its
 *   lobby's share answers 503 node_busy and does nothing; no other lobby's
 *   calls are touched. The table holds every slot's share and reserve, so a
 *   live lobby's id is never dropped; an ended lobby's go oldest first when
 *   room is needed, after those past their 30 days.
 * - With no object (pause, the signing setting): the newest GZ_API_RING, in
 *   a ring. A replay of an older one acts again, and is answered by the
 *   current state: the pause already in that state, or based_on_version. */
#define GZ_API_LOBBY_SHARE         64
#define GZ_API_LOBBY_RESERVE       4
#define GZ_API_MAX_REQUESTS        544 /* GZ_NODE_MAX_SLOTS x (share + reserve) */
#define GZ_API_RING                32

#endif

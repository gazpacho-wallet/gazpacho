/* The test engine (composite-node.md section 2.1): the old placeholder ping,
 * moved behind the composite. Built only into test builds
 * (gazpacho_node_test, GZ_TEST_KINDS); a release node has no test engine and
 * never sees kind 32767. Up to two instances, areas 0x7e57 and 0x7e58.
 *
 * MESSAGES. Kind 32767, scope zero (contract-v2.md section 7). Record 1 is a
 * 4-byte tag and a body; record 3, optional, names the engine (u16 area,
 * 0x7e57 if absent); record 5, optional, is padding the receiver ignores.
 *
 *   GZPI  body: payload (at most 64 bytes)  a ping
 *   GZPO  body: serial (u64), payload       the reply. The serial is the replier's
 *                                            incarnation (high 32 bits) and a count
 *   GZPA  body: serial (u64)                the pinger's acknowledgement
 *   GZPH  body: empty                       hello: send what I have not acknowledged
 *   GZPX  anything                          filler (bursts), ignored
 *
 * WHAT IT GUARANTEES: at least once, to a peer that comes back. If the record
 * of a ping is durable, the reply reaches that link at least once, provided
 * the node goes on running or is started again and the peer connects again
 * with the same keys. It follows the pull model of node.h rule 6: at
 * PEER_CONNECTED on a connection it made, an engine sends GZPH; an engine
 * answers a GZPH, at most once a second per link, with every reply on that
 * link that has no stored acknowledgement, oldest first, at most
 * GZ_TE_RESEND_CHUNK per step (the rest on its continuation timer, one chunk
 * per firing); the pinger answers each reply with GZPA, which the replier
 * saves as an ACKED record. The start saves nothing.
 *
 * RECORDS (area A = the engine's area, record type A << 16 | n):
 *   0x0001 PING     clock (u64), link (local 33, remote 33), serial (u64), payload
 *   0x0004 ACKED    one or more serials (u64)
 *   0x0005 CONNECT  host key (33), key epoch (u32), key index (u32), address
 *   0x0006 HANDOFF_A, 0x0007 HANDOFF_B  a test hand-off's two halves: a u64 tag
 * 0x0002 (contract v1's "sent") and 0x0003 (its restore record) are retired.
 *
 * VIEW. One view object, GZ_VIEW_STATUS with id "test-<area>": version (u64)
 * the number of pings this engine has saved; emitted after each ping's save
 * and at every start (node.h rules 7 and 8).
 *
 * COMMANDS (USER_COMMAND, command.h). Record 10 names the engine (u16 area,
 * 0x7e57 if absent); arguments from 12. Each is answered with a command-result
 * notice after its save, if any.
 *   0x7e01 connect      12 host key (33), 14 address: save CONNECT, then CONNECT (a
 *                       host already saved at another address: the address replaced);
 *                       re-issued at every start (contract-v2.md section 3)
 *   0x7e02 timer        12 delay ms (u32): set the engine's timer id 1
 *   0x7e03 handoff      12 target area (u16), 14 send-between (u8, 0 or 1): save
 *                       HANDOFF_A, [NOTIFY], set timer id 3, hand off to the
 *                       target, which saves HANDOFF_B (one bracket, one batch)
 *   0x7e04 fail         12 after (u32): the engine's step `after` events from now
 *                       appends a save and then returns an error
 *   0x7e05 watch        12 txid (32), 14 depth (u32): WATCH_TX
 *   0x7e06 send         12 remote key (33), 14 kind (u16), 16 scope (32),
 *                       18 records: SEND on the link to that key
 *   0x7e07 big-reply    12 bytes (u32): pad every later reply with record 5
 *   0x7e08 broadcast    a BROADCAST (a bug: only funding broadcasts)
 *   0x7e09 self-handoff hand off to itself: deferred until its call returns
 *   0x7e0a self-handoff-now  the same without deferral: the re-entry check
 *   0x7e0b big-timer    a timer id of 2^32 (a bug)
 *   0x7e0c watch-outpoint 12 txid (32), 14 vout (u32), 16 depth (u32)
 *   0x7e0d flood        12 count (u32): that many log lines in one step (a bug
 *                       past the engine's declared worst step)
 *   0x7e0e two-saves    12 between (u8, 0 or 1): two saves in one step with no
 *                       hand-off, a log line between them if `between`
 * Node-part test commands (slots, test builds):
 *   0x7e80 slot-open    12 scope (32), 14 role (u8: 1 host, 0 member), 16 host
 *                       key (33, member), 18 address (member), 20 timer ms
 *                       (u32, optional), 22 listed (u8, optional)
 *   0x7e81 slot-close   12 scope
 *   0x7e82 slot-seat    12 scope, 14 member key (33), 16 seated (u8)
 *   0x7e83 slot-round   12 scope: the slot's lobby has answered a check / sent
 *                       a start (round kinds may route to signing) */
#ifndef GAZPACHO_TEST_ENGINE_H
#define GAZPACHO_TEST_ENGINE_H

#define GZ_TE_KIND 32767u
#define GZ_TE_REC_TAG     1
#define GZ_TE_REC_AREA    3
#define GZ_TE_REC_PAD     5
#define GZ_TE_MAX_PAYLOAD 64
#define GZ_TE_RESEND_CHUNK 16

#define GZ_TE_PING        0x0001u
#define GZ_TE_ACKED       0x0004u
#define GZ_TE_CONNECT     0x0005u
#define GZ_TE_HANDOFF_A   0x0006u
#define GZ_TE_HANDOFF_B   0x0007u
#define GZ_TE_PING_HEADER 82u   /* clock 8, link 66, serial 8 */

#define GZ_TE_CMD_CONNECT        0x7e01u
#define GZ_TE_CMD_TIMER          0x7e02u
#define GZ_TE_CMD_HANDOFF        0x7e03u
#define GZ_TE_CMD_FAIL           0x7e04u
#define GZ_TE_CMD_WATCH          0x7e05u
#define GZ_TE_CMD_SEND           0x7e06u
#define GZ_TE_CMD_BIG_REPLY      0x7e07u
#define GZ_TE_CMD_BROADCAST      0x7e08u
#define GZ_TE_CMD_SELF_HANDOFF   0x7e09u
#define GZ_TE_CMD_SELF_HANDOFF_NOW 0x7e0au
#define GZ_TE_CMD_BIG_TIMER      0x7e0bu
#define GZ_TE_CMD_WATCH_OUTPOINT 0x7e0cu
#define GZ_TE_CMD_FLOOD          0x7e0du
#define GZ_TE_CMD_TWO_SAVES      0x7e0eu
#define GZ_TE_CMD_SLOT_OPEN      0x7e80u
#define GZ_TE_CMD_SLOT_CLOSE     0x7e81u
#define GZ_TE_CMD_SLOT_SEAT      0x7e82u
#define GZ_TE_CMD_SLOT_ROUND     0x7e83u

#endif

/* User commands and notices (contract-v2.md section 11; composite-node.md
 * section 5).
 *
 * A GZ_EVENT_USER_COMMAND carries a TLV stream (envelope.h):
 *
 *   0  request_id  printable ASCII, 1 to 64 bytes (the client's), required
 *   2  method      ASCII
 *   4  path        ASCII
 *   6  digest      32 bytes
 *   8  command     u16, big-endian: a GZ_CMD_* code, required
 *   10 and up      the command's arguments
 *
 * The composite routes a command by its code's high byte, the AREA RANGE:
 * 0x01xx lobby (the command names the slot), 0x03xx funding, 0x04xx node
 * (the signing gate), 0x0dxx local API, 0x7exx test (test builds only). A
 * code no engine takes, or a command without a code, is answered with the
 * command-result notice `unknown_command` (status 404): a user can send
 * anything, so it is never an error (node.h, the engine rule).
 *
 * A NOTIFY's code says what its bytes are; the bytes are a TLV stream:
 *
 *   GZ_NOTIFY_VIEW(k)        a view object of kind k: 0 id (1 to 64 bytes of
 *                            printable ASCII), required; 2 gone (empty) when
 *                            the object is removed; 4 version (u64), which
 *                            grows with every change of the object (the
 *                            simulator checks that a view rebuilt at start is
 *                            never older than one released before a stop);
 *                            then the object's own fields from 6.
 *   GZ_NOTIFY_COMMAND_RESULT 0 request_id, required; 2 status (u16: 200, 202,
 *                            or the error status); 4 error (an error code of
 *                            local-api.md 8.1, ASCII), absent on success;
 *                            6 object; 8 params.
 *   GZ_NOTIFY_LOG            0 text, printable ASCII, never a secret. */
#ifndef GAZPACHO_COMMAND_H
#define GAZPACHO_COMMAND_H

#include "gazpacho/types.h"

#define GZ_NOTIFY_VIEW(k)          (0x00010000u + (uint32_t)(k))
#define GZ_NOTIFY_COMMAND_RESULT   0x00020000u
#define GZ_NOTIFY_LOG              0x00030000u

/* View object kinds (contract-v2.md section 11). */
#define GZ_VIEW_STATUS      1
#define GZ_VIEW_LOBBY       2
#define GZ_VIEW_HOST_LOBBY  3
#define GZ_VIEW_FACTORY     4
#define GZ_VIEW_WALLET      5
#define GZ_VIEW_ACTIVITY    6
#define GZ_VIEW_ATTENTION   7
#define GZ_VIEW_DOING       8
#define GZ_VIEW_CONNECTION  9

/* Records of a view object. */
#define GZ_VIEW_REC_ID      0
#define GZ_VIEW_REC_GONE    2
#define GZ_VIEW_REC_VERSION 4

/* Records of a USER_COMMAND. */
#define GZ_CMD_REC_REQUEST_ID 0
#define GZ_CMD_REC_METHOD     2
#define GZ_CMD_REC_PATH       4
#define GZ_CMD_REC_DIGEST     6
#define GZ_CMD_REC_COMMAND    8
#define GZ_CMD_REC_ARGS       10   /* the first argument's type */

/* Records of a command-result notice. */
#define GZ_RESULT_REC_REQUEST_ID 0
#define GZ_RESULT_REC_STATUS     2
#define GZ_RESULT_REC_ERROR      4

#define GZ_CMD_MAX_REQUEST_ID 64

/* The area range of a command code. */
#define GZ_CMD_RANGE(code)   ((uint16_t)(code) >> 8)
#define GZ_CMD_RANGE_LOBBY   0x01
#define GZ_CMD_RANGE_FUNDING 0x03
#define GZ_CMD_RANGE_NODE    0x04
#define GZ_CMD_RANGE_API     0x0d
#define GZ_CMD_RANGE_TEST    0x7e

#endif

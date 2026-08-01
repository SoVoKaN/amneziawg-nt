#pragma once

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2026 Mark Kraus <mark@sovokan.com>. All Rights Reserved.
 */

#include <ntdef.h>

/* MAX_PREFIX_SIZE_DATA is sized against the NBL pools in memory.c, whose largest bucket is 9000
 * bytes. A data packet is allocated as inner packet + framing + prefix, and a sum above 9000
 * misses every bucket and falls back to a per-packet ExAllocatePool and MDL build. 4096 is a
 * round number with comfortable margin, not a tuned limit.
 */
#define MAX_PREFIX_SIZE_DATA 4096

/* Sizes of the random junk prefix prepended to each outgoing message type, stored in two
 * different units - the three handshake fields are totals, Data is a bare prefix length.
 *
 * The handshake messages are fixed-length structs, so HandshakeInitiation, HandshakeResponse
 * and HandshakeCookie hold the *total* on-wire size of that message: prefix + sizeof(MESSAGE_*).
 * Holding the total is what lets the receive path classify an incoming packet by comparing
 * Buffer->Length against these fields for exact equality. They are seeded to sizeof(MESSAGE_*)
 * at device init and are therefore never zero.
 *
 * MESSAGE_DATA ends in a flexible array, so a transport packet has no single on-wire size to
 * compare against. Data therefore holds *only* the prefix length, with zero meaning "no junk".
 * The receive path bounds-checks against Data + MESSAGE_MINIMUM_LENGTH and skips Data bytes.
 */
typedef DECLSPEC_ALIGN(8) union _MESSAGE_PREFIX_SIZES
{
    struct
    {
        USHORT HandshakeInitiation;
        USHORT HandshakeResponse;
        USHORT HandshakeCookie;
        USHORT Data;
    };
    ULONG64 Raw; /* Snapshots all four sizes in one atomic access */
} MESSAGE_PREFIX_SIZES;
static_assert(
    sizeof(MESSAGE_PREFIX_SIZES) == sizeof(ULONG64),
    "MESSAGE_PREFIX_SIZES is too large for a single atomic access");

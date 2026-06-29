#pragma once

/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2026 Mark Kraus <mark@sovokan.com>. All Rights Reserved.
 */

#include <ntdef.h>

#define MAX_JUNK_COUNT 128

typedef DECLSPEC_ALIGN(8) union _JUNK_PACKETS
{
    struct
    {
        USHORT Count;
        struct
        {
            USHORT Min;
            USHORT Max;
        } Size;
        USHORT : 16; /* Padding to 64 bits */
    };
    ULONG64 Raw;
} JUNK_PACKETS;
static_assert(sizeof(JUNK_PACKETS) == sizeof(ULONG64), "JUNK_PACKETS is too large for a single atomic access");

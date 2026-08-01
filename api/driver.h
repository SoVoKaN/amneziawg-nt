/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "amneziawg.h"
#include <Windows.h>
#include <SetupAPI.h>

#define AMNEZIAWG_HWID L"AmneziaWG"

typedef struct _SP_DEVINFO_DATA_LIST SP_DEVINFO_DATA_LIST;

VOID
DriverInstallDeferredCleanup(_In_ HDEVINFO DevInfoExistingAdapters, _In_opt_ SP_DEVINFO_DATA_LIST *ExistingAdapters);

_Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL
DriverInstall(
    _Out_ HDEVINFO *DevInfoExistingAdaptersForCleanup,
    _Out_ SP_DEVINFO_DATA_LIST **ExistingAdaptersForCleanup);

/**
 * @copydoc AMNEZIAWG_DELETE_DRIVER_FUNC
 */
AMNEZIAWG_DELETE_DRIVER_FUNC AmneziaWGDeleteDriver;

/**
 * @copydoc AMNEZIAWG_GET_RUNNING_DRIVER_VERSION_FUNC
 */
AMNEZIAWG_GET_RUNNING_DRIVER_VERSION_FUNC AmneziaWGGetRunningDriverVersion;

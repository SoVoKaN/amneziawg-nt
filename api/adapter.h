/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include "amneziawg.h"
#include <IPExport.h>
#include <SetupAPI.h>
#include <cfgmgr32.h>
#include <Windows.h>

#define AMNEZIAWG_HWID L"AmneziaWG"
#define AMNEZIAWG_ENUMERATOR L"SWD\\" AMNEZIAWG_HWID

extern const DEVPROPKEY DEVPKEY_AmneziaWG_Name;

typedef struct HSWDEVICE__ *HSWDEVICE;

/**
 * AmneziaWG adapter descriptor.
 */
typedef struct _AMNEZIAWG_ADAPTER
{
    HSWDEVICE SwDevice;
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    WCHAR *InterfaceFilename;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_DEVICE_ID_LEN];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
    HANDLE LogThread;
    DWORD LogState;
} AMNEZIAWG_ADAPTER;
/**
 * @copydoc AMNEZIAWG_CREATE_ADAPTER_FUNC
 */
AMNEZIAWG_CREATE_ADAPTER_FUNC AmneziaWGCreateAdapter;

/**
 * @copydoc AMNEZIAWG_OPEN_ADAPTER_FUNC
 */
AMNEZIAWG_OPEN_ADAPTER_FUNC AmneziaWGOpenAdapter;

/**
 * @copydoc AMNEZIAWG_CLOSE_ADAPTER_FUNC
 */
AMNEZIAWG_CLOSE_ADAPTER_FUNC AmneziaWGCloseAdapter;

/**
 * @copydoc AMNEZIAWG_GET_ADAPTER_LUID_FUNC
 */
AMNEZIAWG_GET_ADAPTER_LUID_FUNC AmneziaWGGetAdapterLUID;

/**
 * Returns a handle to the adapter device object.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGOpenAdapter or AmneziaWGCreateAdapter.
 *
 * @return If the function succeeds, the return value is adapter device object handle.
 *         If the function fails, the return value is INVALID_HANDLE_VALUE. To get extended error
 *         information, call GetLastError.
 */
_Return_type_success_(return != INVALID_HANDLE_VALUE)
HANDLE WINAPI
AdapterOpenDeviceObject(_In_ const AMNEZIAWG_ADAPTER *Adapter);

/**
 * Returns the device object file name for an adapter instance ID.
 *
 * @param InstanceID       The device instance ID of the adapter.
 *
 * @return If the function succeeds, the return value is the filename of the device object, which
 *         must be freed with Free(). If the function fails, the return value is INVALID_HANDLE_VALUE.
 *         To get extended error information, call GetLastError.
 */
_Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
LPWSTR
AdapterGetDeviceObjectFileName(_In_z_ LPCWSTR InstanceId);

/**
 * Cleans up adapters with no attached process.
 */
VOID AdapterCleanupOrphanedDevices(BOOL Background);

/**
 * Removes the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterRemoveInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Enables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterEnableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

/**
 * Disables the specified device instance.
 *
 * @param DevInfo      Device info handle from SetupAPI.
 * @param DevInfoData  Device info data specifying which device.
 *
 * @return If the function succeeds, the return value is TRUE. If the
 *         function fails, the return value is FALSE. To get extended
 *         error information, call GetLastError.
 */

_Return_type_success_(return != FALSE)
BOOL
AdapterDisableInstance(_In_ HDEVINFO DevInfo, _In_ SP_DEVINFO_DATA *DevInfoData);

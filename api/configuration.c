/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 */

#include "../driver/ioctl.h"
#include "amneziawg.h"
#include "adapter.h"
#include "logger.h"
#include <Windows.h>
#include <stdlib.h>

static_assert(sizeof(AWG_IOCTL_INTERFACE) == sizeof(AMNEZIAWG_INTERFACE), "Interface struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_INTERFACE, Flags) == offsetof(AMNEZIAWG_INTERFACE, Flags),
    "Interface->Flags struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_INTERFACE, Flags) == RTL_FIELD_SIZE(AMNEZIAWG_INTERFACE, Flags),
    "Interface->Flags struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_INTERFACE, ListenPort) == offsetof(AMNEZIAWG_INTERFACE, ListenPort),
    "Interface->ListenPort struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_INTERFACE, ListenPort) == RTL_FIELD_SIZE(AMNEZIAWG_INTERFACE, ListenPort),
    "Interface->ListenPort struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_INTERFACE, PrivateKey) == offsetof(AMNEZIAWG_INTERFACE, PrivateKey),
    "Interface->PrivateKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_INTERFACE, PrivateKey) == RTL_FIELD_SIZE(AMNEZIAWG_INTERFACE, PrivateKey),
    "Interface->PrivateKey struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_INTERFACE, PublicKey) == offsetof(AMNEZIAWG_INTERFACE, PublicKey),
    "Interface->PublicKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_INTERFACE, PublicKey) == RTL_FIELD_SIZE(AMNEZIAWG_INTERFACE, PublicKey),
    "Interface->PublicKey struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_INTERFACE, PeersCount) == offsetof(AMNEZIAWG_INTERFACE, PeersCount),
    "Interface->PeersCount struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_INTERFACE, PeersCount) == RTL_FIELD_SIZE(AMNEZIAWG_INTERFACE, PeersCount),
    "Interface->PeersCount struct mismatch");
static_assert(
    (DWORD)AWG_IOCTL_INTERFACE_HAS_PUBLIC_KEY == (DWORD)AMNEZIAWG_INTERFACE_HAS_PUBLIC_KEY,
    "INTERFACE_HAS_PUBLIC_KEY flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_INTERFACE_HAS_PRIVATE_KEY == (DWORD)AMNEZIAWG_INTERFACE_HAS_PRIVATE_KEY,
    "INTERFACE_HAS_PRIVATE_KEY flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_INTERFACE_HAS_LISTEN_PORT == (DWORD)AMNEZIAWG_INTERFACE_HAS_LISTEN_PORT,
    "INTERFACE_HAS_LISTEN_PORT flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_INTERFACE_REPLACE_PEERS == (DWORD)AMNEZIAWG_INTERFACE_REPLACE_PEERS,
    "INTERFACE_REPLACE_PEERS flag mismatch");
static_assert(sizeof(AWG_IOCTL_PEER) == sizeof(AMNEZIAWG_PEER), "Peer struct mismatch");
static_assert(offsetof(AWG_IOCTL_PEER, Flags) == offsetof(AMNEZIAWG_PEER, Flags), "Peer->Flags struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, Flags) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, Flags),
    "Peer->Flags struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, ProtocolVersion) == offsetof(AMNEZIAWG_PEER, Reserved),
    "Peer->Reserved struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, ProtocolVersion) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, Reserved),
    "Peer->Reserved struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, PublicKey) == offsetof(AMNEZIAWG_PEER, PublicKey),
    "Peer->PublicKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, PublicKey) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, PublicKey),
    "Peer->PublicKey struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, PresharedKey) == offsetof(AMNEZIAWG_PEER, PresharedKey),
    "Peer->PresharedKey struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, PresharedKey) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, PresharedKey),
    "Peer->PresharedKey struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, PersistentKeepalive) == offsetof(AMNEZIAWG_PEER, PersistentKeepalive),
    "Peer->PersistentKeepalive struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, PersistentKeepalive) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, PersistentKeepalive),
    "Peer->PersistentKeepalive struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, Endpoint) == offsetof(AMNEZIAWG_PEER, Endpoint),
    "Peer->Endpoint struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, Endpoint) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, Endpoint),
    "Peer->Endpoint struct mismatch");
static_assert(offsetof(AWG_IOCTL_PEER, TxBytes) == offsetof(AMNEZIAWG_PEER, TxBytes), "Peer->TxBytes struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, TxBytes) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, TxBytes),
    "Peer->TxBytes struct mismatch");
static_assert(offsetof(AWG_IOCTL_PEER, RxBytes) == offsetof(AMNEZIAWG_PEER, RxBytes), "Peer->RxBytes struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, RxBytes) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, RxBytes),
    "Peer->RxBytes struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, LastHandshake) == offsetof(AMNEZIAWG_PEER, LastHandshake),
    "Peer->LastHandshake struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, LastHandshake) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, LastHandshake),
    "Peer->LastHandshake struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_PEER, AllowedIPsCount) == offsetof(AMNEZIAWG_PEER, AllowedIPsCount),
    "Peer->AllowedIPsCount struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_PEER, AllowedIPsCount) == RTL_FIELD_SIZE(AMNEZIAWG_PEER, AllowedIPsCount),
    "Peer->AllowedIPsCount struct mismatch");
static_assert(
    (DWORD)AWG_IOCTL_PEER_HAS_PUBLIC_KEY == (DWORD)AMNEZIAWG_PEER_HAS_PUBLIC_KEY,
    "PEER_HAS_PUBLIC_KEY flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_PEER_HAS_PRESHARED_KEY == (DWORD)AMNEZIAWG_PEER_HAS_PRESHARED_KEY,
    "PEER_HAS_PRESHARED_KEY flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE == (DWORD)AMNEZIAWG_PEER_HAS_PERSISTENT_KEEPALIVE,
    "PEER_HAS_PERSISTENT_KEEPALIVE flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_PEER_HAS_ENDPOINT == (DWORD)AMNEZIAWG_PEER_HAS_ENDPOINT,
    "PEER_HAS_ENDPOINT flag mismatch");
static_assert(
    (DWORD)AWG_IOCTL_PEER_REPLACE_ALLOWED_IPS == (DWORD)AMNEZIAWG_PEER_REPLACE_ALLOWED_IPS,
    "PEER_REPLACE_ALLOWED_IPS flag mismatch");
static_assert((DWORD)AWG_IOCTL_PEER_REMOVE == (DWORD)AMNEZIAWG_PEER_REMOVE, "PEER_REMOVE flag mismatch");
static_assert((DWORD)AWG_IOCTL_PEER_UPDATE_ONLY == (DWORD)AMNEZIAWG_PEER_UPDATE_ONLY, "PEER_UPDATE_ONLY flag mismatch");
static_assert(sizeof(AWG_IOCTL_ALLOWED_IP) == sizeof(AMNEZIAWG_ALLOWED_IP), "Allowed IP struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, AddressFamily) == offsetof(AMNEZIAWG_ALLOWED_IP, AddressFamily),
    "AllowedIp->AddressFamily struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, AddressFamily) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, AddressFamily),
    "AllowedIp->AddressFamily struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, Cidr) == offsetof(AMNEZIAWG_ALLOWED_IP, Cidr),
    "AllowedIp->cidr struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, Cidr) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, Cidr),
    "AllowedIp->cidr struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, Address.V4) == offsetof(AMNEZIAWG_ALLOWED_IP, Address.V4),
    "AllowedIp->Address.V4 struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, Address.V4) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, Address.V4),
    "AllowedIp->Address.V4 struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, Address.V6) == offsetof(AMNEZIAWG_ALLOWED_IP, Address.V6),
    "AllowedIp->Address.V6 struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, Address.V6) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, Address.V6),
    "AllowedIp->Address.V6 struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, Address) == offsetof(AMNEZIAWG_ALLOWED_IP, Address),
    "AllowedIp->Address struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, Address) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, Address),
    "AllowedIp->Address struct mismatch");
static_assert(
    offsetof(AWG_IOCTL_ALLOWED_IP, Flags) == offsetof(AMNEZIAWG_ALLOWED_IP, Flags),
    "AllowedIp->Flags struct mismatch");
static_assert(
    RTL_FIELD_SIZE(AWG_IOCTL_ALLOWED_IP, Flags) == RTL_FIELD_SIZE(AMNEZIAWG_ALLOWED_IP, Flags),
    "AllowedIp->Flags struct mismatch");
static_assert(
    (DWORD)AWG_IOCTL_ALLOWED_IP_REMOVE == (DWORD)AMNEZIAWG_ALLOWED_IP_REMOVE,
    "ALLOWED_IP_REMOVE flag mismatch");
static_assert(sizeof(AWG_IOCTL_ADAPTER_STATE) == sizeof(AMNEZIAWG_ADAPTER_STATE), "Adapter state mismatch");
static_assert(
    (DWORD)AWG_IOCTL_ADAPTER_STATE_DOWN == (DWORD)AMNEZIAWG_ADAPTER_STATE_DOWN,
    "Adapter state down mismatch");
static_assert((DWORD)AWG_IOCTL_ADAPTER_STATE_UP == (DWORD)AMNEZIAWG_ADAPTER_STATE_UP, "Adapter state up mismatch");

AMNEZIAWG_SET_ADAPTER_STATE_FUNC AmneziaWGSetAdapterState;
_Use_decl_annotations_
BOOL WINAPI
AmneziaWGSetAdapterState(AMNEZIAWG_ADAPTER *Adapter, AMNEZIAWG_ADAPTER_STATE State)
{
    switch (State)
    {
    case AMNEZIAWG_ADAPTER_STATE_UP:
    case AMNEZIAWG_ADAPTER_STATE_DOWN:
        break;
    default:
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD BytesReturned;
    if (!DeviceIoControl(
            ControlFile, AWG_IOCTL_SET_ADAPTER_STATE, &State, sizeof(State), NULL, 0, &BytesReturned, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

AMNEZIAWG_GET_ADAPTER_STATE_FUNC AmneziaWGGetAdapterState;
_Use_decl_annotations_
BOOL WINAPI
AmneziaWGGetAdapterState(AMNEZIAWG_ADAPTER *Adapter, AMNEZIAWG_ADAPTER_STATE *State)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    DWORD BytesReturned;
    AWG_IOCTL_ADAPTER_STATE Op = AWG_IOCTL_ADAPTER_STATE_QUERY;
    if (!DeviceIoControl(
            ControlFile, AWG_IOCTL_SET_ADAPTER_STATE, &Op, sizeof(Op), State, sizeof(*State), &BytesReturned, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

AMNEZIAWG_SET_CONFIGURATION_FUNC AmneziaWGSetConfiguration;
_Use_decl_annotations_
BOOL WINAPI
AmneziaWGSetConfiguration(AMNEZIAWG_ADAPTER *Adapter, const AMNEZIAWG_INTERFACE *Config, DWORD Bytes)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!DeviceIoControl(ControlFile, AWG_IOCTL_SET, NULL, 0, (VOID *)Config, Bytes, &Bytes, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

AMNEZIAWG_GET_CONFIGURATION_FUNC AmneziaWGGetConfiguration;
_Use_decl_annotations_
BOOL WINAPI
AmneziaWGGetConfiguration(AMNEZIAWG_ADAPTER *Adapter, AMNEZIAWG_INTERFACE *Config, DWORD *Bytes)
{
    HANDLE ControlFile = AdapterOpenDeviceObject(Adapter);
    if (ControlFile == INVALID_HANDLE_VALUE)
        return FALSE;
    if (!DeviceIoControl(ControlFile, AWG_IOCTL_GET, NULL, 0, Config, *Bytes, Bytes, NULL))
    {
        DWORD LastError = GetLastError();
        CloseHandle(ControlFile);
        SetLastError(LastError);
        return FALSE;
    }
    CloseHandle(ControlFile);
    return TRUE;
}

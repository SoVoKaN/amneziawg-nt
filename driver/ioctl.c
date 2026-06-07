/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2015-2026 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2026 Mark Kraus <mark@sovokan.com>. All Rights Reserved.
 */

#include "device.h"
#include "ioctl.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "logging.h"
#include <ntddk.h>

#define AWG_IOCTL_INTERFACE_HAS_JUNK \
    (AWG_IOCTL_INTERFACE_HAS_JUNK_COUNT | AWG_IOCTL_INTERFACE_HAS_JUNK_MIN_SIZE | AWG_IOCTL_INTERFACE_HAS_JUNK_MAX_SIZE)

#define SIZE_OF_EMBEDDED(A, B) \
    FIELD_OFFSET( \
        struct { \
            A _A; \
            B _B; \
        }, \
        _B)

static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_INTERFACE, AWG_IOCTL_PEER) == (sizeof(AWG_IOCTL_INTERFACE)),
    "Non-symmetric interface stacking");
static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_PEER, AWG_IOCTL_ALLOWED_IP) == SIZE_OF_EMBEDDED(AWG_IOCTL_PEER, AWG_IOCTL_INTERFACE),
    "Non-symmetric peer stacking");
static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_PEER, AWG_IOCTL_ALLOWED_IP) == (sizeof(AWG_IOCTL_PEER)),
    "Non-symmetric peer stacking");
static_assert(SIZE_OF_EMBEDDED(AWG_IOCTL_PEER, AWG_IOCTL_PEER) == (sizeof(AWG_IOCTL_PEER)), "Non-symmetric peer stacking");
static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_ALLOWED_IP, AWG_IOCTL_ALLOWED_IP) == SIZE_OF_EMBEDDED(AWG_IOCTL_ALLOWED_IP, AWG_IOCTL_PEER),
    "Non-symmetric allowed IP stacking");
static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_ALLOWED_IP, AWG_IOCTL_PEER) == (sizeof(AWG_IOCTL_ALLOWED_IP)),
    "Non-symmetric allowed IP stacking");
static_assert(
    SIZE_OF_EMBEDDED(AWG_IOCTL_ALLOWED_IP, AWG_IOCTL_ALLOWED_IP) == (sizeof(AWG_IOCTL_ALLOWED_IP)),
    "Non-symmetric allowed IP stacking");

#undef SIZE_OF_EMBEDDED

static DRIVER_DISPATCH *PriorDispatchDeviceControl, *PriorDispatchCreate, *PriorDispatchPnp;
/* The following binary blob security descriptor was generated via:
 *    PSECURITY_DESCRIPTOR Sd;
 *    ULONG SdLen;
 *    ConvertStringSecurityDescriptorToSecurityDescriptorA("O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NWNRNX;;;HI)",
 *                                                         SDDL_REVISION_1, &Sd, &SdLen);
 *    for (ULONG i = 0; i < SdLen; ++i)
 *        printf("0x%02x%s%s", ((UCHAR *)Sd)[i], i == SdLen - 1 ? "" : ",", i == SdLen - 1 || i % 8 == 7 ? "\n": " ");
 */
static SECURITY_DESCRIPTOR *DispatchSecurityDescriptor = (SECURITY_DESCRIPTOR *)(DECLSPEC_ALIGN(8) UCHAR[]){
    0x01, 0x00, 0x14, 0x90, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x14, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x30, 0x00, 0x00, 0x02, 0x00, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x14, 0x00, 0xff, 0x01, 0x1f, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x18, 0x00, 0xff, 0x01, 0x1f, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00,
    0x00, 0x20, 0x02, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00
};

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
HasAccess(_In_ ACCESS_MASK DesiredAccess, _In_ KPROCESSOR_MODE AccessMode, _Out_ NTSTATUS *Status)
{
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    SeCaptureSubjectContext(&SubjectContext);
    ACCESS_MASK GrantedAccess;
    BOOLEAN HasAccess = SeAccessCheck(
        DispatchSecurityDescriptor,
        &SubjectContext,
        FALSE,
        DesiredAccess,
        0,
        NULL,
        IoGetFileObjectGenericMapping(),
        AccessMode,
        &GrantedAccess,
        Status);
    SeReleaseSubjectContext(&SubjectContext);
    return HasAccess;
}

static AWG_DEVICE *
WgDeviceFromFdo(_In_ DEVICE_OBJECT *DeviceObject)
{
    if (DeviceObject->DeviceType != FILE_DEVICE_PHYSICAL_NETCARD || !DeviceObject->DeviceExtension)
        return NULL;
    return NdisWdfGetAdapterContextFromAdapterHandle(DeviceObject->DeviceExtension);
}

static inline VOID
GetJunkPackets(_In_ CONST AWG_DEVICE *Wg, _Inout_ AWG_IOCTL_INTERFACE *IoctlInterface)
{
    JUNK_PACKETS Junk = { .Raw = ReadULong64NoFence(&Wg->JunkPackets.Raw) };
    IoctlInterface->JunkCount = Junk.Count;
    IoctlInterface->JunkMinSize = Junk.Size.Min;
    IoctlInterface->JunkMaxSize = Junk.Size.Max;
    IoctlInterface->Flags |= AWG_IOCTL_INTERFACE_HAS_JUNK_COUNT | AWG_IOCTL_INTERFACE_HAS_JUNK_MIN_SIZE |
                             AWG_IOCTL_INTERFACE_HAS_JUNK_MAX_SIZE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Get(_In_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
    Irp->IoStatus.Information = 0;
    if (!HasAccess(FILE_READ_DATA, Irp->RequestorMode, &Irp->IoStatus.Status))
        return;

    AWG_IOCTL_INTERFACE *IoctlInterface = NULL;
    if (Irp->MdlAddress)
    {
        IoctlInterface = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);
        if (!IoctlInterface)
        {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            return;
        }
    }

    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (!Wg || ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Irp->IoStatus.Status = NDIS_STATUS_ADAPTER_REMOVED;
        return;
    }

    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);

    ULONG OutSize = IoctlInterface ? MmGetMdlByteCount(Irp->MdlAddress) : 0;
    ULONG64 FinalSize = sizeof(AWG_IOCTL_INTERFACE);
    if (OutSize >= FinalSize)
    {
        IoctlInterface->Flags = 0;
        IoctlInterface->PeersCount = 0;
        if (Wg->IncomingPort != 0)
        {
            IoctlInterface->ListenPort = Wg->IncomingPort;
            IoctlInterface->Flags |= AWG_IOCTL_INTERFACE_HAS_LISTEN_PORT;
        }
        MuAcquirePushLockShared(&Wg->StaticIdentity.Lock);
        if (Wg->StaticIdentity.HasIdentity)
        {
            RtlCopyMemory(IoctlInterface->PrivateKey, Wg->StaticIdentity.StaticPrivate, NOISE_PUBLIC_KEY_LEN);
            RtlCopyMemory(IoctlInterface->PublicKey, Wg->StaticIdentity.StaticPublic, NOISE_PUBLIC_KEY_LEN);
            IoctlInterface->Flags |= AWG_IOCTL_INTERFACE_HAS_PUBLIC_KEY | AWG_IOCTL_INTERFACE_HAS_PRIVATE_KEY;
        }
        MuReleasePushLockShared(&Wg->StaticIdentity.Lock);
        GetJunkPackets(Wg, IoctlInterface);
    }

    AWG_IOCTL_PEER *IoctlPeer = (AWG_IOCTL_PEER *)((UCHAR *)IoctlInterface + sizeof(AWG_IOCTL_INTERFACE));
    AWG_PEER *Peer;
    LIST_FOR_EACH_ENTRY (Peer, &Wg->PeerList, PeerList)
    {
        FinalSize += sizeof(AWG_IOCTL_PEER);
        if (OutSize >= FinalSize)
        {
            ++IoctlInterface->PeersCount;
            IoctlPeer->Flags = AWG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE;
            IoctlPeer->ProtocolVersion = 1;
            IoctlPeer->PersistentKeepalive = Peer->PersistentKeepaliveInterval;
            IoctlPeer->RxBytes = Peer->RxBytes;
            IoctlPeer->TxBytes = Peer->TxBytes;
            IoctlPeer->LastHandshake = Peer->WalltimeLastHandshake.QuadPart;
            IoctlPeer->AllowedIPsCount = 0;
            MuAcquirePushLockShared(&Peer->Handshake.Lock);
            RtlCopyMemory(IoctlPeer->PublicKey, Peer->Handshake.RemoteStatic, NOISE_PUBLIC_KEY_LEN);
            IoctlPeer->Flags |= AWG_IOCTL_PEER_HAS_PUBLIC_KEY;
            if (!CryptoIsZero32(Peer->Handshake.PresharedKey))
            {
                RtlCopyMemory(IoctlPeer->PresharedKey, Peer->Handshake.PresharedKey, NOISE_SYMMETRIC_KEY_LEN);
                IoctlPeer->Flags |= AWG_IOCTL_PEER_HAS_PRESHARED_KEY;
            }
            MuReleasePushLockShared(&Peer->Handshake.Lock);
            KIRQL Irql;
            Irql = ExAcquireSpinLockShared(&Peer->EndpointLock);
            if (Peer->Endpoint.Addr.si_family == AF_INET)
            {
                IoctlPeer->Endpoint.Ipv4 = Peer->Endpoint.Addr.Ipv4;
                IoctlPeer->Flags |= AWG_IOCTL_PEER_HAS_ENDPOINT;
            }
            else if (Peer->Endpoint.Addr.si_family == AF_INET6)
            {
                IoctlPeer->Endpoint.Ipv6 = Peer->Endpoint.Addr.Ipv6;
                IoctlPeer->Flags |= AWG_IOCTL_PEER_HAS_ENDPOINT;
            }
            ExReleaseSpinLockShared(&Peer->EndpointLock, Irql);
        }

        AWG_IOCTL_ALLOWED_IP *IoctlAllowedIp = (AWG_IOCTL_ALLOWED_IP *)((UCHAR *)IoctlPeer + sizeof(AWG_IOCTL_PEER));
        ALLOWEDIPS_NODE *AllowedIpsNode;
        ULONG AllowedIpsLimit = MAXULONG;
        LIST_FOR_EACH_ENTRY (AllowedIpsNode, &Peer->AllowedIpsList, PeerList)
        {
            if (!(--AllowedIpsLimit))
                break;
            FinalSize += sizeof(AWG_IOCTL_ALLOWED_IP);
            if (OutSize >= FinalSize)
            {
                ++IoctlPeer->AllowedIPsCount;
                IoctlAllowedIp->AddressFamily =
                    AllowedIpsReadNode(AllowedIpsNode, (UINT8 *)&IoctlAllowedIp->Address, &IoctlAllowedIp->Cidr);
                IoctlAllowedIp->Flags = 0;
            }
            ++IoctlAllowedIp;
        }
        IoctlPeer = (AWG_IOCTL_PEER *)IoctlAllowedIp;
    }
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);

    Irp->IoStatus.Status = OutSize >= FinalSize    ? STATUS_SUCCESS
                           : FinalSize <= MAXULONG ? STATUS_BUFFER_OVERFLOW
                                                   : STATUS_SECTION_TOO_BIG;
    Irp->IoStatus.Information = (ULONG_PTR)FinalSize;
}

_Requires_lock_held_(Wg->DeviceUpdateLock)
static inline JUNK_PACKETS
MergeJunkPackets(_In_ CONST AWG_DEVICE *Wg, _In_ CONST AWG_IOCTL_INTERFACE *IoctlInterface)
{
    JUNK_PACKETS Junk = { .Raw = Wg->JunkPackets.Raw };
    if (IoctlInterface->Flags & AWG_IOCTL_INTERFACE_HAS_JUNK_COUNT)
        Junk.Count = IoctlInterface->JunkCount;
    if (IoctlInterface->Flags & AWG_IOCTL_INTERFACE_HAS_JUNK_MIN_SIZE)
        Junk.Size.Min = IoctlInterface->JunkMinSize;
    if (IoctlInterface->Flags & AWG_IOCTL_INTERFACE_HAS_JUNK_MAX_SIZE)
        Junk.Size.Max = IoctlInterface->JunkMaxSize;
    return Junk;
}

_Must_inspect_result_
static inline NTSTATUS
ValidateJunkPackets(_In_ CONST JUNK_PACKETS Junk)
{
    if (Junk.Size.Min > Junk.Size.Max)
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

_Requires_lock_held_(Wg->DeviceUpdateLock)
static inline VOID
SetJunkPackets(_Inout_ AWG_DEVICE *Wg, _In_ CONST JUNK_PACKETS Junk)
{
    Wg->JunkPackets.Raw = Junk.Raw;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Requires_lock_held_(Wg->DeviceUpdateLock)
_Must_inspect_result_
static NTSTATUS
SetListenPort(_Inout_ AWG_DEVICE *Wg, _In_ USHORT ListenPort)
{
    if (Wg->IncomingPort == ListenPort)
        return STATUS_SUCCESS;
    AWG_PEER *Peer;
    LIST_FOR_EACH_ENTRY (Peer, &Wg->PeerList, PeerList)
        SocketClearPeerEndpointSrc(Peer);
    if (ReadBooleanNoFence(&Wg->IsUp))
        return SocketInit(Wg, ListenPort);
    Wg->IncomingPort = ListenPort;
    return STATUS_SUCCESS;
}

_Requires_lock_held_(Wg->DeviceUpdateLock)
_Must_inspect_result_
static NTSTATUS
SetPrivateKey(_Inout_ AWG_DEVICE *Wg, _In_ CONST UCHAR PrivateKey[AWG_KEY_LEN])
{
    UINT8 PublicKey[NOISE_PUBLIC_KEY_LEN];
    BOOLEAN SendStagedPackets;
    AWG_PEER *Peer, *Temp;

    if (CryptoEqualMemory32(Wg->StaticIdentity.StaticPrivate, PrivateKey))
        return STATUS_SUCCESS;

    /* We remove before setting, to prevent race, which means doing two 25519-genpub ops. */
    if (Curve25519GeneratePublic(PublicKey, PrivateKey))
    {
        Peer = PubkeyHashtableLookup(Wg->PeerHashtable, PublicKey);
        if (Peer)
        {
            PeerPut(Peer);
            _Analysis_assume_same_lock_(Peer->Device->DeviceUpdateLock, Wg->DeviceUpdateLock);
            PeerRemove(Peer);
        }
    }

    MuAcquirePushLockExclusive(&Wg->StaticIdentity.Lock);
    SendStagedPackets = !Wg->StaticIdentity.HasIdentity && ReadBooleanNoFence(&Wg->IsUp);
    NoiseSetStaticIdentityPrivateKey(&Wg->StaticIdentity, PrivateKey);
    SendStagedPackets = SendStagedPackets && Wg->StaticIdentity.HasIdentity;
    _Analysis_assume_same_lock_(Wg->CookieChecker.Device->DeviceUpdateLock, Wg->DeviceUpdateLock);
    CookieCheckerPrecomputeDeviceKeys(&Wg->CookieChecker);
    LIST_FOR_EACH_ENTRY_SAFE (Peer, Temp, &Wg->PeerList, PeerList)
    {
        _Analysis_assume_same_lock_(Peer->Device->DeviceUpdateLock, Wg->DeviceUpdateLock);
        NoisePrecomputeStaticStatic(Peer);
        NoiseExpireCurrentPeerKeypairs(Peer);
        if (SendStagedPackets)
            PacketSendStagedPackets(Peer);
    }
    MuReleasePushLockExclusive(&Wg->StaticIdentity.Lock);
    return STATUS_SUCCESS;
}

_Requires_lock_held_(Wg->DeviceUpdateLock)
_Must_inspect_result_
static NTSTATUS
SetPeer(_Inout_ AWG_DEVICE *Wg, _Inout_ CONST volatile AWG_IOCTL_PEER **UnsafeIoctlPeerPtr, _Inout_ ULONG *RemainingSize)
{
    if (*RemainingSize < sizeof(AWG_IOCTL_PEER))
        return STATUS_INVALID_PARAMETER;
    *RemainingSize -= sizeof(AWG_IOCTL_PEER);

    CONST volatile AWG_IOCTL_PEER *UnsafeIoctlPeer = *UnsafeIoctlPeerPtr;
    AWG_IOCTL_PEER IoctlPeer = *UnsafeIoctlPeer;

    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    if (!(IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_PUBLIC_KEY))
        goto cleanupStack;
    Status = STATUS_NOT_IMPLEMENTED;
    if ((IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_PROTOCOL_VERSION) && IoctlPeer.ProtocolVersion != 0 &&
        IoctlPeer.ProtocolVersion > 1)
        goto cleanupStack;
    Status = STATUS_INVALID_PARAMETER;
    ULONG AllowedIPsSize;
    if (!NT_SUCCESS(RtlULongMult(IoctlPeer.AllowedIPsCount, sizeof(AWG_IOCTL_ALLOWED_IP), &AllowedIPsSize)))
        goto cleanupStack;
    if (*RemainingSize < AllowedIPsSize)
        goto cleanupStack;
    *RemainingSize -= AllowedIPsSize;
    CONST volatile AWG_IOCTL_ALLOWED_IP *UnsafeIoctlAllowedIp =
        (CONST volatile AWG_IOCTL_ALLOWED_IP *)((UCHAR *)UnsafeIoctlPeer + sizeof(AWG_IOCTL_PEER));
    *UnsafeIoctlPeerPtr = (CONST AWG_IOCTL_PEER *)((UCHAR *)UnsafeIoctlAllowedIp + AllowedIPsSize);

    Status = STATUS_SUCCESS;
    AWG_PEER *Peer = PubkeyHashtableLookup(Wg->PeerHashtable, IoctlPeer.PublicKey);
    if (!Peer)
    {
        /* Peer doesn't exist yet. Add a new one. */
        if (IoctlPeer.Flags & (AWG_IOCTL_PEER_REMOVE | AWG_IOCTL_PEER_UPDATE_ONLY))
            goto cleanupStack;

        /* The peer is new, so there aren't allowed IPs to remove. */
        IoctlPeer.Flags &= ~AWG_IOCTL_PEER_REPLACE_ALLOWED_IPS;

        MuAcquirePushLockShared(&Wg->StaticIdentity.Lock);
        if (Wg->StaticIdentity.HasIdentity &&
            RtlEqualMemory(IoctlPeer.PublicKey, Wg->StaticIdentity.StaticPublic, NOISE_PUBLIC_KEY_LEN))
        {
            /* We silently ignore peers that have the same public key as the device. The reason we do it silently is
             * that we'd like for people to be able to reuse the same set of API calls across peers. */
            MuReleasePushLockShared(&Wg->StaticIdentity.Lock);
            goto cleanupStack;
        }
        MuReleasePushLockShared(&Wg->StaticIdentity.Lock);

        Status = PeerCreate(
            Wg,
            IoctlPeer.PublicKey,
            (IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_PRESHARED_KEY) ? IoctlPeer.PresharedKey : NULL,
            &Peer);
        if (!NT_SUCCESS(Status))
            goto cleanupStack;
        /* Take additional reference, as though we've just been looked up. */
        PeerGet(Peer);
    }

    if (IoctlPeer.Flags & AWG_IOCTL_PEER_REMOVE)
    {
        _Analysis_assume_same_lock_(Peer->Device->DeviceUpdateLock, Wg->DeviceUpdateLock);
        PeerRemove(Peer);
        Status = STATUS_SUCCESS;
        goto cleanupPeer;
    }

    if (IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_PRESHARED_KEY)
    {
        MuAcquirePushLockExclusive(&Peer->Handshake.Lock);
        RtlCopyMemory(&Peer->Handshake.PresharedKey, IoctlPeer.PresharedKey, NOISE_SYMMETRIC_KEY_LEN);
        MuReleasePushLockExclusive(&Peer->Handshake.Lock);
    }

    if (IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_ENDPOINT)
    {
        SIZE_T Size;
        if ((Size = sizeof(SOCKADDR_IN), IoctlPeer.Endpoint.si_family == AF_INET) ||
            (Size = sizeof(SOCKADDR_IN6), IoctlPeer.Endpoint.si_family == AF_INET6))
        {
            ENDPOINT Endpoint = { { { 0 } } };
            RtlCopyMemory(&Endpoint.Addr, &IoctlPeer.Endpoint, Size);
            SocketSetPeerEndpoint(Peer, &Endpoint);
        }
    }

    if (IoctlPeer.Flags & AWG_IOCTL_PEER_REPLACE_ALLOWED_IPS)
        AllowedIpsRemoveByPeer(&Wg->PeerAllowedIps, Peer, &Wg->DeviceUpdateLock);

    for (ULONG i = 0; i < IoctlPeer.AllowedIPsCount; ++i)
    {
        AWG_IOCTL_ALLOWED_IP IoctlAllowedIp = UnsafeIoctlAllowedIp[i];
        if (IoctlAllowedIp.AddressFamily == AF_INET && IoctlAllowedIp.Cidr <= 32)
        {
            if (IoctlAllowedIp.Flags & AWG_IOCTL_ALLOWED_IP_REMOVE)
                Status = AllowedIpsRemoveV4(
                    &Peer->Device->PeerAllowedIps,
                    &IoctlAllowedIp.Address.V4,
                    IoctlAllowedIp.Cidr,
                    Peer,
                    &Wg->DeviceUpdateLock);
            else
                Status = AllowedIpsInsertV4(
                    &Peer->Device->PeerAllowedIps,
                    &IoctlAllowedIp.Address.V4,
                    IoctlAllowedIp.Cidr,
                    Peer,
                    &Wg->DeviceUpdateLock);
        }
        else if (IoctlAllowedIp.AddressFamily == AF_INET6 && IoctlAllowedIp.Cidr <= 128)
        {
            if (IoctlAllowedIp.Flags & AWG_IOCTL_ALLOWED_IP_REMOVE)
                Status = AllowedIpsRemoveV6(
                    &Peer->Device->PeerAllowedIps,
                    &IoctlAllowedIp.Address.V6,
                    IoctlAllowedIp.Cidr,
                    Peer,
                    &Wg->DeviceUpdateLock);
            else
                Status = AllowedIpsInsertV6(
                    &Peer->Device->PeerAllowedIps,
                    &IoctlAllowedIp.Address.V6,
                    IoctlAllowedIp.Cidr,
                    Peer,
                    &Wg->DeviceUpdateLock);
        }
        else
            Status = STATUS_INVALID_PARAMETER;
        if (!NT_SUCCESS(Status))
            goto cleanupPeer;
    }

    BOOLEAN IsUp = ReadBooleanNoFence(&Wg->IsUp);
    if (IoctlPeer.Flags & AWG_IOCTL_PEER_HAS_PERSISTENT_KEEPALIVE)
    {
        CONST BOOLEAN SendKeepalive = !Peer->PersistentKeepaliveInterval && IoctlPeer.PersistentKeepalive && IsUp;
        Peer->PersistentKeepaliveInterval = IoctlPeer.PersistentKeepalive;
        if (SendKeepalive)
            PacketSendKeepalive(Peer);
    }

    if (IsUp)
        PacketSendStagedPackets(Peer);

    Status = STATUS_SUCCESS;
cleanupPeer:
    PeerPut(Peer);
cleanupStack:
    RtlSecureZeroMemory(&IoctlPeer, sizeof(IoctlPeer));
    return Status;
}

/* C4701: ProposedJunk is conditionally initialized and read under the identical HAS_JUNK gate, so the
 * "potentially uninitialized" path is unreachable. C4701 is reported at function scope, so suppress-on-line
 * does not catch it; it must be disabled around the whole function. */
#pragma warning(push)
#pragma warning(disable : 4701)
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
SetInterface(
    _Inout_ AWG_DEVICE *Wg,
    _In_ CONST volatile AWG_IOCTL_INTERFACE *UnsafeIoctlInterface,
    _Inout_ ULONG *RemainingSize)
{
    if (*RemainingSize < sizeof(AWG_IOCTL_INTERFACE))
        return STATUS_INVALID_PARAMETER;
    *RemainingSize = *RemainingSize - sizeof(AWG_IOCTL_INTERFACE);

    AWG_IOCTL_INTERFACE IoctlInterface = *UnsafeIoctlInterface;

    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_HAS_JUNK_COUNT)
        if (IoctlInterface.JunkCount > MAX_JUNK_COUNT)
            return STATUS_INVALID_PARAMETER;

    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);

    NTSTATUS Status;

    JUNK_PACKETS ProposedJunk;
    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_HAS_JUNK)
    {
        ProposedJunk = MergeJunkPackets(Wg, &IoctlInterface);
        Status = ValidateJunkPackets(ProposedJunk);
        if (!NT_SUCCESS(Status))
            goto cleanupLock;
    }

    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_HAS_JUNK)
        SetJunkPackets(Wg, ProposedJunk);

    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_HAS_LISTEN_PORT)
    {
        Status = SetListenPort(Wg, IoctlInterface.ListenPort);
        if (!NT_SUCCESS(Status))
            goto cleanupLock;
    }

    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_REPLACE_PEERS)
        PeerRemoveAll(Wg);

    if (IoctlInterface.Flags & AWG_IOCTL_INTERFACE_HAS_PRIVATE_KEY)
    {
        Status = SetPrivateKey(Wg, IoctlInterface.PrivateKey);
        if (!NT_SUCCESS(Status))
            goto cleanupLock;
    }

    CONST volatile AWG_IOCTL_PEER *UnsafeIoctlPeer =
        (CONST volatile AWG_IOCTL_PEER *)((UCHAR *)UnsafeIoctlInterface + sizeof(AWG_IOCTL_INTERFACE));
    for (ULONG i = 0; i < IoctlInterface.PeersCount; ++i)
    {
        Status = SetPeer(Wg, &UnsafeIoctlPeer, RemainingSize);
        if (!NT_SUCCESS(Status))
            goto cleanupLock;
    }

    Status = STATUS_SUCCESS;
cleanupLock:
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);
    RtlSecureZeroMemory(&IoctlInterface, sizeof(IoctlInterface));
    return Status;
}
#pragma warning(pop)

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Set(_In_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
    Irp->IoStatus.Information = 0;
    if (!HasAccess(FILE_WRITE_DATA, Irp->RequestorMode, &Irp->IoStatus.Status))
        return;

    if (!Irp->MdlAddress)
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        return;
    }
    CONST volatile AWG_IOCTL_INTERFACE *UnsafeIoctlInterface =
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
    if (!UnsafeIoctlInterface)
    {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        return;
    }

    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (!Wg || ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Irp->IoStatus.Status = NDIS_STATUS_ADAPTER_REMOVED;
        return;
    }

    ULONG InSize = MmGetMdlByteCount(Irp->MdlAddress);
    ULONG RemainingSize = InSize;
    Irp->IoStatus.Status = SetInterface(Wg, UnsafeIoctlInterface, &RemainingSize);
    Irp->IoStatus.Information = InSize - RemainingSize;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Requires_lock_held_(&Wg->DeviceUpdateLock)
static NTSTATUS
Up(_Inout_ AWG_DEVICE *Wg)
{
    if (ReadBooleanNoFence(&Wg->IsUp))
        return STATUS_ALREADY_COMPLETE;
    NT_ASSERT(!Wg->SocketOwnerProcess);
    Wg->SocketOwnerProcess = PsGetCurrentProcess();
    if (Wg->SocketOwnerProcess)
        ObReferenceObject(Wg->SocketOwnerProcess);
    NTSTATUS Status = SocketInit(Wg, Wg->IncomingPort);
    if (!NT_SUCCESS(Status))
    {
        if (Wg->SocketOwnerProcess)
        {
            ObDereferenceObject(Wg->SocketOwnerProcess);
            Wg->SocketOwnerProcess = NULL;
        }
        return Status;
    }
    WriteBooleanNoFence(&Wg->IsUp, TRUE);
    DeviceStart(Wg);
    DeviceIndicateConnectionStatus(Wg->MiniportAdapterHandle, MediaConnectStateConnected);
    LogInfo(Wg, "Interface up");
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Requires_lock_held_(&Wg->DeviceUpdateLock)
static NTSTATUS
Down(_Inout_ AWG_DEVICE *Wg)
{
    if (!ReadBooleanNoFence(&Wg->IsUp))
        return STATUS_ALREADY_COMPLETE;
    WriteBooleanNoFence(&Wg->IsUp, FALSE);
    RcuSynchronize();
    DeviceIndicateConnectionStatus(Wg->MiniportAdapterHandle, MediaConnectStateDisconnected);
    DeviceStop(Wg);
    SocketReinit(Wg, NULL, NULL, 0);
    if (Wg->SocketOwnerProcess)
    {
        ObDereferenceObject(Wg->SocketOwnerProcess);
        Wg->SocketOwnerProcess = NULL;
    }
    LogInfo(Wg, "Interface down");
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
AdapterState(_In_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
    Irp->IoStatus.Information = 0;
    if (!HasAccess(FILE_WRITE_DATA, Irp->RequestorMode, &Irp->IoStatus.Status))
        return;
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(AWG_IOCTL_ADAPTER_STATE))
    {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        return;
    }
    AWG_IOCTL_ADAPTER_STATE Op;
    RtlCopyMemory(&Op, Irp->AssociatedIrp.SystemBuffer, sizeof(Op));

    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (!Wg || ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Irp->IoStatus.Status = NDIS_STATUS_ADAPTER_REMOVED;
        return;
    }
    MuAcquirePushLockExclusive(&Wg->DeviceUpdateLock);
    switch (Op)
    {
    case AWG_IOCTL_ADAPTER_STATE_QUERY:
        if (Stack->Parameters.DeviceIoControl.OutputBufferLength == sizeof(Op))
        {
            Op = ReadBooleanNoFence(&Wg->IsUp) ? AWG_IOCTL_ADAPTER_STATE_UP : AWG_IOCTL_ADAPTER_STATE_DOWN;
            RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Op, sizeof(Op));
            Irp->IoStatus.Information = sizeof(Op);
        }
        else
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        break;
    case AWG_IOCTL_ADAPTER_STATE_DOWN:
        Irp->IoStatus.Status = Down(Wg);
        break;
    case AWG_IOCTL_ADAPTER_STATE_UP:
        Irp->IoStatus.Status = Up(Wg);
        break;
    default:
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
    }
    MuReleasePushLockExclusive(&Wg->DeviceUpdateLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
ReadLogLine(_In_ DEVICE_OBJECT *DeviceObject, _Inout_ IRP *Irp)
{
    Irp->IoStatus.Information = 0;
    if (!HasAccess(FILE_READ_DATA, Irp->RequestorMode, &Irp->IoStatus.Status))
        return;

    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (!Wg || ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Irp->IoStatus.Status = NDIS_STATUS_ADAPTER_REMOVED;
        return;
    }

    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AWG_IOCTL_LOG_ENTRY))
    {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    Irp->IoStatus.Status = LogRingRead(&Wg->Log, Irp->AssociatedIrp.SystemBuffer, &Wg->IsDeviceRemoving);
    if (NT_SUCCESS(Irp->IoStatus.Status))
        Irp->IoStatus.Information = sizeof(AWG_IOCTL_LOG_ENTRY);
}

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH_PAGED DispatchDeviceControl;
_Use_decl_annotations_
static NTSTATUS
DispatchDeviceControl(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    switch (Stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case AWG_IOCTL_GET:
        Get(DeviceObject, Irp);
        break;
    case AWG_IOCTL_SET:
        Set(DeviceObject, Irp);
        break;
    case AWG_IOCTL_SET_ADAPTER_STATE:
        AdapterState(DeviceObject, Irp);
        break;
    case AWG_IOCTL_READ_LOG_LINE:
        ReadLogLine(DeviceObject, Irp);
        break;
    default:
        return PriorDispatchDeviceControl(DeviceObject, Irp);
    }
    NTSTATUS Status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

_Dispatch_type_(IRP_MJ_CREATE)
static DRIVER_DISPATCH DispatchCreate;
_Use_decl_annotations_
static NTSTATUS
DispatchCreate(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (Wg && ReadBooleanNoFence(&Wg->IsDeviceRemoving))
    {
        Irp->IoStatus.Status = NDIS_STATUS_ADAPTER_REMOVED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return NDIS_STATUS_ADAPTER_REMOVED;
    }
    return PriorDispatchCreate(DeviceObject, Irp);
}

_Dispatch_type_(IRP_MJ_PNP)
static DRIVER_DISPATCH DispatchPnp;
_Use_decl_annotations_
static NTSTATUS
DispatchPnp(DEVICE_OBJECT *DeviceObject, IRP *Irp)
{
    IO_STACK_LOCATION *Stack = IoGetCurrentIrpStackLocation(Irp);
    if (Stack->MinorFunction != IRP_MN_QUERY_REMOVE_DEVICE && Stack->MinorFunction != IRP_MN_SURPRISE_REMOVAL)
        goto ndisDispatch;

    AWG_DEVICE *Wg = WgDeviceFromFdo(DeviceObject);
    if (!Wg)
        goto ndisDispatch;
    WriteBooleanNoFence(&Wg->IsDeviceRemoving, TRUE);
    KeSetEvent(&Wg->Log.NewEntry, IO_NO_INCREMENT, FALSE);

ndisDispatch:
    return PriorDispatchPnp(DeviceObject, Irp);
}

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, IoctlDriverEntry)
#endif
_Use_decl_annotations_
VOID
IoctlDriverEntry(DRIVER_OBJECT *DriverObject)
{
    PriorDispatchDeviceControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    PriorDispatchCreate = DriverObject->MajorFunction[IRP_MJ_CREATE];
    PriorDispatchPnp = DriverObject->MajorFunction[IRP_MJ_PNP];
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_PNP] = DispatchPnp;
}

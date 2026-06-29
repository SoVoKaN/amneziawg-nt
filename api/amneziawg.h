/* SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
 */

#pragma once

#include <winsock2.h>
#include <windows.h>
#include <ipexport.h>
#include <ifdef.h>
#include <ws2ipdef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ALIGNED
#    if defined(_MSC_VER)
#        define ALIGNED(n) __declspec(align(n))
#    elif defined(__GNUC__)
#        define ALIGNED(n) __attribute__((aligned(n)))
#    else
#        error "Unable to define ALIGNED"
#    endif
#endif

/* MinGW is missing this one, unfortunately. */
#ifndef _Post_maybenull_
#    define _Post_maybenull_
#endif

#pragma warning(push)
#pragma warning(disable : 4324) /* structure was padded due to alignment specifier */

/**
 * A handle representing AmneziaWG adapter
 */
typedef struct _AMNEZIAWG_ADAPTER *AMNEZIAWG_ADAPTER_HANDLE;

/**
 * Creates a new AmneziaWG adapter.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param TunnelType    Name of the adapter tunnel type. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @param RequestedGUID The GUID of the created network adapter, which then influences NLA generation deterministically.
 *                      If it is set to NULL, the GUID is chosen by the system at random, and hence a new NLA entry is
 *                      created for each new adapter. It is called "requested" GUID because the API it uses is
 *                      completely undocumented, and so there could be minor interesting complications with its usage.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with
 * AmneziaWGCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call
 * GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
AMNEZIAWG_ADAPTER_HANDLE(WINAPI AMNEZIAWG_CREATE_ADAPTER_FUNC)
(_In_z_ LPCWSTR Name, _In_z_ LPCWSTR TunnelType, _In_opt_ const GUID *RequestedGUID);

/**
 * Opens an existing AmneziaWG adapter.
 *
 * @param Name          The requested name of the adapter. Zero-terminated string of up to MAX_ADAPTER_NAME-1
 *                      characters.
 *
 * @return If the function succeeds, the return value is the adapter handle. Must be released with
 * AmneziaWGCloseAdapter. If the function fails, the return value is NULL. To get extended error information, call
 * GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != NULL)
_Post_maybenull_
AMNEZIAWG_ADAPTER_HANDLE(WINAPI AMNEZIAWG_OPEN_ADAPTER_FUNC)(_In_z_ LPCWSTR Name);

/**
 * Releases AmneziaWG adapter resources and, if adapter was created with AmneziaWGCreateAdapter, removes adapter.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter.
 */
typedef VOID(WINAPI AMNEZIAWG_CLOSE_ADAPTER_FUNC)(_In_opt_ AMNEZIAWG_ADAPTER_HANDLE Adapter);

/**
 * Deletes the AmneziaWG driver if there are no more adapters in use.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_DELETE_DRIVER_FUNC)(VOID);

/**
 * Returns the LUID of the adapter.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param Luid          Pointer to LUID to receive adapter LUID.
 */
typedef VOID(WINAPI AMNEZIAWG_GET_ADAPTER_LUID_FUNC)(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid);

/**
 * Determines the version of the AmneziaWG driver currently loaded.
 *
 * @return If the function succeeds, the return value is the version number. If the function fails, the return value is
 *         zero. To get extended error information, call GetLastError. Possible errors include the following:
 *         ERROR_FILE_NOT_FOUND  AmneziaWG not loaded
 */
typedef _Return_type_success_(return != 0)
DWORD(WINAPI AMNEZIAWG_GET_RUNNING_DRIVER_VERSION_FUNC)(VOID);

/**
 * Determines the level of logging, passed to AMNEZIAWG_LOGGER_CALLBACK.
 */
typedef enum
{
    AMNEZIAWG_LOG_INFO, /**< Informational */
    AMNEZIAWG_LOG_WARN, /**< Warning */
    AMNEZIAWG_LOG_ERR   /**< Error */
} AMNEZIAWG_LOGGER_LEVEL;

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
 *
 * @param Message       Message text.
 */
typedef VOID(CALLBACK *AMNEZIAWG_LOGGER_CALLBACK)(
    _In_ AMNEZIAWG_LOGGER_LEVEL Level,
    _In_ DWORD64 Timestamp,
    _In_z_ LPCWSTR Message);

/**
 * Sets logger callback function.
 *
 * @param NewLogger     Pointer to callback function to use as a new global logger. NewLogger may be called from various
 *                      threads concurrently. Should the logging require serialization, you must handle serialization in
 *                      NewLogger. Set to NULL to disable.
 */
typedef VOID(WINAPI AMNEZIAWG_SET_LOGGER_FUNC)(_In_ AMNEZIAWG_LOGGER_CALLBACK NewLogger);

/**
 * Whether and how logs from the driver are collected for the callback function.
 */
typedef enum
{
    AMNEZIAWG_ADAPTER_LOG_OFF,           /**< No logs are generated from the driver. */
    AMNEZIAWG_ADAPTER_LOG_ON,            /**< Logs are generated from the driver. */
    AMNEZIAWG_ADAPTER_LOG_ON_WITH_PREFIX /**< Logs are generated from the driver, index-prefixed. */
} AMNEZIAWG_ADAPTER_LOG_STATE;

/**
 * Sets whether and how the adapter logs to the logger previously set up with AmneziaWGSetLogger.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param LogState      Adapter logging state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_SET_ADAPTER_LOGGING_FUNC)
(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter, _In_ AMNEZIAWG_ADAPTER_LOG_STATE LogState);

/**
 * Determines the state of the adapter.
 */
typedef enum
{
    AMNEZIAWG_ADAPTER_STATE_DOWN, /**< Down */
    AMNEZIAWG_ADAPTER_STATE_UP,   /**< Up */
} AMNEZIAWG_ADAPTER_STATE;

/**
 * Sets the adapter state of the AmneziaWG adapter. Note: sockets are owned by the process that sets the state to up.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param State         Adapter state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_SET_ADAPTER_STATE_FUNC)
(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter, _In_ AMNEZIAWG_ADAPTER_STATE State);

/**
 * Gets the adapter state of the AmneziaWG adapter.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param State         Pointer to adapter state.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_GET_ADAPTER_STATE_FUNC)
(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter, _Out_ AMNEZIAWG_ADAPTER_STATE *State);

#define AMNEZIAWG_KEY_LENGTH 32

typedef enum
{
    AMNEZIAWG_ALLOWED_IP_REMOVE = 1 << 0 /**< Remove the specified allowed IP instead of adding it to the peer. */
} AMNEZIAWG_ALLOWED_IP_FLAG;
DEFINE_ENUM_FLAG_OPERATORS(AMNEZIAWG_ALLOWED_IP_FLAG)

typedef struct _AMNEZIAWG_ALLOWED_IP AMNEZIAWG_ALLOWED_IP;
struct ALIGNED(8) _AMNEZIAWG_ALLOWED_IP
{
    union
    {
        IN_ADDR V4;
        IN6_ADDR V6;
    } Address;                       /**< IP address */
    ADDRESS_FAMILY AddressFamily;    /**< Address family, either AF_INET or AF_INET6 */
    BYTE Cidr;                       /**< CIDR of allowed IPs */
    AMNEZIAWG_ALLOWED_IP_FLAG Flags; /**< Bitwise combination of flags */
};

typedef enum
{
    AMNEZIAWG_PEER_HAS_PUBLIC_KEY = 1 << 0,           /**< The PublicKey field is set */
    AMNEZIAWG_PEER_HAS_PRESHARED_KEY = 1 << 1,        /**< The PresharedKey field is set */
    AMNEZIAWG_PEER_HAS_PERSISTENT_KEEPALIVE = 1 << 2, /**< The PersistentKeepAlive field is set */
    AMNEZIAWG_PEER_HAS_ENDPOINT = 1 << 3,             /**< The Endpoint field is set */
    AMNEZIAWG_PEER_REPLACE_ALLOWED_IPS = 1 << 5,      /**< Remove all allowed IPs before adding new ones */
    AMNEZIAWG_PEER_REMOVE = 1 << 6,                   /**< Remove specified peer */
    AMNEZIAWG_PEER_UPDATE_ONLY = 1 << 7               /**< Do not add a new peer */
} AMNEZIAWG_PEER_FLAG;
DEFINE_ENUM_FLAG_OPERATORS(AMNEZIAWG_PEER_FLAG)

typedef struct _AMNEZIAWG_PEER AMNEZIAWG_PEER;
struct ALIGNED(8) _AMNEZIAWG_PEER
{
    AMNEZIAWG_PEER_FLAG Flags;               /**< Bitwise combination of flags */
    DWORD Reserved;                          /**< Reserved; must be zero */
    BYTE PublicKey[AMNEZIAWG_KEY_LENGTH];    /**< Public key, the peer's primary identifier */
    BYTE PresharedKey[AMNEZIAWG_KEY_LENGTH]; /**< Preshared key for additional layer of post-quantum resistance */
    WORD PersistentKeepalive;                /**< Seconds interval, or 0 to disable */
    SOCKADDR_INET Endpoint;                  /**< Endpoint, with IP address and UDP port number*/
    DWORD64 TxBytes;                         /**< Number of bytes transmitted */
    DWORD64 RxBytes;                         /**< Number of bytes received */
    DWORD64 LastHandshake;                   /**< Time of the last handshake, in 100ns intervals since 1601-01-01 UTC */
    DWORD AllowedIPsCount;                   /**< Number of allowed IP structs following this struct */
};

typedef enum
{
    AMNEZIAWG_INTERFACE_HAS_PUBLIC_KEY = 1 << 0,    /**< The PublicKey field is set */
    AMNEZIAWG_INTERFACE_HAS_PRIVATE_KEY = 1 << 1,   /**< The PrivateKey field is set */
    AMNEZIAWG_INTERFACE_HAS_LISTEN_PORT = 1 << 2,   /**< The ListenPort field is set */
    AMNEZIAWG_INTERFACE_REPLACE_PEERS = 1 << 3,     /**< Remove all peers before adding new ones */
    AMNEZIAWG_INTERFACE_HAS_JUNK_COUNT = 1 << 4,    /**< The JunkCount field is set */
    AMNEZIAWG_INTERFACE_HAS_JUNK_MIN_SIZE = 1 << 5, /**< The JunkMinSize field is set */
    AMNEZIAWG_INTERFACE_HAS_JUNK_MAX_SIZE = 1 << 6  /**< The JunkMaxSize field is set */
} AMNEZIAWG_INTERFACE_FLAG;
DEFINE_ENUM_FLAG_OPERATORS(AMNEZIAWG_INTERFACE_FLAG)

typedef struct _AMNEZIAWG_INTERFACE AMNEZIAWG_INTERFACE;
struct ALIGNED(8) _AMNEZIAWG_INTERFACE
{
    AMNEZIAWG_INTERFACE_FLAG Flags;        /**< Bitwise combination of flags */
    WORD ListenPort;                       /**< Port for UDP listen socket, or 0 to choose randomly */
    BYTE PrivateKey[AMNEZIAWG_KEY_LENGTH]; /**< Private key of interface */
    BYTE PublicKey[AMNEZIAWG_KEY_LENGTH];  /**< Corresponding public key of private key */
    WORD JunkCount;                        /**< Number of junk packets sent before each handshake initiation */
    DWORD PeersCount;                      /**< Number of peer structs following this struct */
    WORD JunkMinSize;                      /**< Minimum size in bytes of each junk packet */
    WORD JunkMaxSize;                      /**< Maximum size in bytes of each junk packet */
};

/**
 * Sets the configuration of the AmneziaWG adapter.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param Config        Configuration for the adapter.
 *
 * @param Bytes         Number of bytes in Config allocation.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError.
 */
typedef _Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_SET_CONFIGURATION_FUNC)
(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter, _In_reads_bytes_(Bytes) const AMNEZIAWG_INTERFACE *Config, _In_ DWORD Bytes);

/**
 * Gets the configuration of the AmneziaWG adapter.
 *
 * @param Adapter       Adapter handle obtained with AmneziaWGCreateAdapter or AmneziaWGOpenAdapter
 *
 * @param Config        Configuration for the adapter.
 *
 * @param Bytes         Pointer to number of bytes in Config allocation.
 *
 * @return If the function succeeds, the return value is nonzero. If the function fails, the return value is zero. To
 *         get extended error information, call GetLastError, which if ERROR_MORE_DATA, Bytes is updated with the
 *         required size.
 */
typedef _Must_inspect_result_
_Return_type_success_(return != FALSE)
BOOL(WINAPI AMNEZIAWG_GET_CONFIGURATION_FUNC)
(_In_ AMNEZIAWG_ADAPTER_HANDLE Adapter,
 _Out_writes_bytes_all_(*Bytes) AMNEZIAWG_INTERFACE *Config,
 _Inout_ DWORD *Bytes);

#pragma warning(pop)

#ifdef __cplusplus
}
#endif

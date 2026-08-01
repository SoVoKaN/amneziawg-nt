# AmneziaWG for the NT Kernel
### High performance in-kernel AmneziaWG implementation for Windows

AmneziaWGNT is an implementation of AmneziaWG, for the NT Kernel as used in Windows 10 and 11, supporting AMD64 and ARM64 processors.

#### Not the droids you're looking for

**If you've come here looking to run AmneziaWG on Windows, you're in the wrong place. Instead, head on over to the AmneziaWG Download Page to download the AmneziaWG application.** Alternatively, if you've come here looking to embed AmneziaWG into your Windows program, **you are still in the wrong place**. Instead, head on over to the embeddable DLL service project, to get everything you need to bake AmneziaWG into your Windows programs. These projects use AmneziaWGNT inside.

## Usage

#### Download

AmneziaWG is deployed as a platform-specific `amneziawg.dll` file. Install the `amneziawg.dll` file side-by-side with your application. Download the dll from the amneziawg-nt download server, alongside the header file for your application described below.

#### API

Include the `amneziawg.h` file in your project simply by copying it there and dynamically load the `amneziawg.dll` using [`LoadLibraryEx()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) and [`GetProcAddress()`](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) to resolve each function, using the typedefs provided in the header file. The `InitializeAmneziaWGNT` function in the example.c code provides this in a function that you can simply copy and paste.

With the library setup, AmneziaWGNT can then be used by first creating an adapter, configuring it, and then setting its status to "up". Adapters have names (e.g. "OfficeNet") and types (e.g. "AmneziaWG").

```C
AMNEZIAWG_ADAPTER_HANDLE Adapter1 = AmneziaWGCreateAdapter(L"OfficeNet", L"AmneziaWG", &SomeFixedGUID1);
AMNEZIAWG_ADAPTER_HANDLE Adapter2 = AmneziaWGCreateAdapter(L"HomeNet", L"AmneziaWG", &SomeFixedGUID2);
AMNEZIAWG_ADAPTER_HANDLE Adapter3 = AmneziaWGCreateAdapter(L"Data Center", L"AmneziaWG", &SomeFixedGUID3);
```

After creating an adapter, we can use it by setting a configuration and setting its status to "up":

```C
struct
{
    AMNEZIAWG_INTERFACE Interface;
    AMNEZIAWG_PEER FirstPeer;
    AMNEZIAWG_ALLOWED_IP FirstPeerAllowedIP1;
    AMNEZIAWG_ALLOWED_IP FirstPeerAllowedIP2;
    AMNEZIAWG_PEER SecondPeer;
    AMNEZIAWG_ALLOWED_IP SecondtPeerAllowedIP1;
} Config = {
    .Interface = {
        .Flags = AMNEZIAWG_INTERFACE_HAS_PRIVATE_KEY,
        .PrivateKey = ...,
        .PeersCount = 2
    },
    .FirstPeer = {
        .Flags = AMNEZIAWG_PEER_HAS_PUBLIC_KEY | AMNEZIAWG_PEER_HAS_ENDPOINT,
        .PublicKey = ...,
        .Endpoint = ...,
        .AllowedIPsCount = 2
    },
    .FirstPeerAllowedIP1 = { ... },
    ...
};
AmneziaWGSetConfiguration(Adapter1, &Config.Interface, sizeof(Config));
AmneziaWGSetAdapterState(Adapter1, AMNEZIAWG_ADAPTER_STATE_UP);
```

You are *highly encouraged* to read the **example.c short example** to see how to put together a simple network tunnel. The example one connects to the [demo server](https://demo.wireguard.com/).

The various functions and definitions are documented in `amneziawg.h` as well as in the reference below.

## API Reference

### Type:  `AMNEZIAWG_ADAPTER_HANDLE` - opaque type to an instance of an AmneziaWG adapter.

### Function: `AmneziaWGCreateAdapter` - creates a new adapter.

```c
AMNEZIAWG_ADAPTER_HANDLE AmneziaWGCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const GUID *RequestedGUID);
```

Typedef'd as `AMNEZIAWG_CREATE_ADAPTER_FUNC`. Returns an `AMNEZIAWG_ADAPTER_HANDLE` if successful, which must be released with `AmneziaWGCloseAdapter`; otherwise returns `NULL` and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`LPCWSTR`|Name|The requested name of the adapter. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|
|`LPCWSTR`|TunnelType|Name of the adapter tunnel type. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|
|`GUID *`|RequestedGUID|The GUID of the created network adapter, which then influences NLA generation deterministically. If it is set to `NULL`, the GUID is chosen by the system at random, and hence a new NLA entry is created for each new adapter.|

### Function: `AmneziaWGOpenAdapter` - opens an existing adapter.

```c
AMNEZIAWG_ADAPTER_HANDLE AmneziaWGOpenAdapter(LPCWSTR Name);
```

Typedef'd as `AMNEZIAWG_OPEN_ADAPTER_FUNC`. Returns an `AMNEZIAWG_ADAPTER_HANDLE` if successful, which must be released with `AmneziaWGCloseAdapter`; otherwise returns `NULL` and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`LPCWSTR`|Name|The requested name of the adapter. Zero-terminated string of up to `MAX_ADAPTER_NAME-1` characters.|

### Function: `AmneziaWGCloseAdapter` - closes an open adapter and releases its resources.

```c
VOID AmneziaWGCloseAdapter(AMNEZIAWG_ADAPTER_HANDLE Adapter);
```

Typedef'd as `AMNEZIAWG_CLOSE_ADAPTER_FUNC`. Releases AmneziaWG adapter resources and, if adapter was created with `AmneziaWGCreateAdapter`, removes adapter.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|

### Function: `AmneziaWGGetAdapterLUID` - gets the LUID of an adapter.

```c
VOID AmneziaWGGetAdapterLUID(AMNEZIAWG_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
```

Typedef'd as `AMNEZIAWG_GET_ADAPTER_LUID_FUNC`. Returns the LUID of the adapter into the variable passed as the `Luid` argument.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`NET_LUID *` (out)|Luid|Pointer to receive adapter LUID.|

### Function: `AmneziaWGGetRunningDriverVersion` - gets the version of the loaded driver.

```c
DWORD AmneziaWGGetRunningDriverVersion(VOID);
```

Typedef'd as `AMNEZIAWG_GET_RUNNING_DRIVER_VERSION_FUNC`. Returns the version of the AmneziaWGNT driver currently loaded, or zero on error and sets LastError, which is `ERROR_FILE_NOT_FOUND` if AmneziaWGNT is not currently loaded.

### Function: `AmneziaWGDeleteDriver` - deletes driver if not in use.

```c
BOOL AmneziaWGDeleteDriver(VOID);
```

Typedef'd as `AMNEZIAWG_DELETE_DRIVER_FUNC`. Deletes the AmneziaWGNT driver if there are no more adapters in use, and returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

### Enumeration: `AMNEZIAWG_LOGGER_LEVEL` - determines level of logging.

|Name|Description|
|--|--|
|`AMNEZIAWG_LOG_INFO`|Informational|
|`AMNEZIAWG_LOG_WARN`|Warning|
|`AMNEZIAWG_LOG_ERR`|Error|

### Callback type: `AMNEZIAWG_LOGGER_CALLBACK` - called for each log message.

```c
VOID AmneziaWGLoggerCallback(AMNEZIAWG_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message);
```

Typedef'd as `AMNEZIAWG_LOGGER_CALLBACK`. Called by the library on each log message.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_LOGGER_LEVEL`|Level|Message level.|
|`DWORD64`|Timestamp|Message timestamp in in 100ns intervals since 1601-01-01 UTC.|
|`LPCWSTR`|Message|Message text.|

### Function: `AmneziaWGSetLogger` - registers logger callback function.

```c
VOID AmneziaWGSetLogger(AMNEZIAWG_LOGGER_CALLBACK NewLogger);
```

Typedef'd as `AMNEZIAWG_SET_LOGGER_FUNC`. After registration, the callback may be called concurrently by multiple threads. It is up to the supplied callback function, `NewLogger`, to handle synchronization. If `NewLogger` is `NULL`, logging is disabled.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_LOGGER_CALLBACK`|NewLogger|Pointer to callback function to use as a new global logger.|

### Enumeration: `AMNEZIAWG_ADAPTER_LOG_STATE` - determines adapter log generation.

|Name|Description|
|--|--|
|`AMNEZIAWG_ADAPTER_LOG_OFF`|No logs are generated from the driver.|
|`AMNEZIAWG_ADAPTER_LOG_ON`|Logs are generated from the driver.|
|`AMNEZIAWG_ADAPTER_LOG_ON_WITH_PREFIX`|Logs are generated from the driver, adapter index-prefixed.|

### Function: `AmneziaWGSetAdapterLogging` - sets whether adapter logs are generated.

```c
BOOL AmneziaWGSetAdapterLogging(AMNEZIAWG_ADAPTER_HANDLE Adapter, AMNEZIAWG_ADAPTER_LOG_STATE LogState);
```

Typedef'd as `AMNEZIAWG_SET_ADAPTER_LOGGING`.  Sets whether and how the specified adapter logs to the logger previously set by `AmneziaWGSetLogger`.  Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`AMNEZIAWG_ADAPTER_LOG_STATE`|LogState|Adapter logging state.|

### Enumeration: `AMNEZIAWG_ADAPTER_STATE` - determines adapter state.

|Name|Description|
|--|--|
|`AMNEZIAWG_ADAPTER_STATE_DOWN`|Down|
|`AMNEZIAWG_ADAPTER_STATE_UP`|Up|

### Function: `AmneziaWGSetAdapterState` - sets state of adapter.

```c
BOOL AmneziaWGSetAdapterState(AMNEZIAWG_ADAPTER_HANDLE Adapter, AMNEZIAWG_ADAPTER_STATE State);
```

Typedef'd as `AMNEZIAWG_SET_ADAPTER_STATE`.  Sets the specified adapter up or down. Note that sockets used by the specified adapter are owned by the process that sets the adapter up. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`AMNEZIAWG_ADAPTER_STATE`|State|Adapter state.|

### Function: `AmneziaWGGetAdapterState` - gets state of adapter.

```c
BOOL AmneziaWGGetAdapterState(AMNEZIAWG_ADAPTER_HANDLE Adapter, AMNEZIAWG_ADAPTER_STATE *State);
```

Typedef'd as `AMNEZIAWG_GET_ADAPTER_STATE`.  Gets whether the specified adapter is up or down. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`AMNEZIAWG_ADAPTER_STATE` (out)|State|Pointer to adapter state.|

### Structure: `AMNEZIAWG_INTERFACE` - an interface.

|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_INTERFACE_FLAG`|Flags|Bitwise combination of flags.|
|`WORD`|ListenPort|Port for UDP listen socket, or 0 to choose randomly.|
|`BYTE[AMNEZIAWG_KEY_LENGTH]`|PrivateKey|Private key of interface.| 
|`BYTE[AMNEZIAWG_KEY_LENGTH]`|PublicKey|Corresponding public key of private key (unused on set).|
|`DWORD`|PeersCount|Number of peer structures following this structure.|

### Structure: `AMNEZIAWG_PEER` - a peer.

|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_PEER_FLAG`|Flags|Bitwise combination of flags.|
|`DWORD`|Reserved|Reserved; must be zero.|
|`BYTE[AMNEZIAWG_KEY_LENGTH]`|PublicKey|Public key, the peer's primary identifier.|
|`BYTE[AMNEZIAWG_KEY_LENGTH]`|PresharedKey|Preshared key for additional layer of post-quantum resistance.|
|`WORD`|PersistentKeepalive|Persistent keep-alive seconds interval, or 0 to disable.|
|`SOCKADDR_INET`|Endpoint|Endpoint, with IP address and UDP port number.|
|`DWORD64`|TxBytes|Number of bytes transmitted (unused on set).|
|`DWORD64`|RxBytes|Number of bytes received (unused on set).|
|`DWORD64`|LastHandshake|Time of the last handshake, in 100ns intervals since 1601-01-01 UTC (unused on set).|
|`DWORD`|AllowedIPsCount|Number of allowed IP structures following this structure.|

### Structure: `AMNEZIAWG_ALLOWED_IP` - an IP network range.

|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ALLOWED_IP_FLAG`|Flags|Bitwise combination of flags.|
|Union|Address|IP address; the `V4` member is a `IN_ADDR` and the `V6` member is a `IN6_ADDR`.|
|`ADDRESS_FAMILY`|AddressFamily|Address family, either `AF_INET` or `AF_INET6`.|
|`BYTE`|Cidr|The CIDR of the address range.|

### Constant: `AMNEZIAWG_KEY_LENGTH` - the length of a key.

All AmneziaWG keys -- public, private, or pre-shared -- are 32 bytes in length.

### Enumeration: `AMNEZIAWG_INTERFACE_FLAG` - bitwise flags for interfaces.

These values may be or'd together.

|Name|Description|
|--|--|
|`AMNEZIAWG_INTERFACE_HAS_PUBLIC_KEY`|The PublicKey field is set (unused on set).|
|`AMNEZIAWG_INTERFACE_HAS_PRIVATE_KEY`|The PrivateKey field is set.|
|`AMNEZIAWG_INTERFACE_HAS_LISTEN_PORT`|The ListenPort field is set.|
|`AMNEZIAWG_INTERFACE_REPLACE_PEERS`|Remove all peers before adding new ones (unused on get).|

### Enumeration: `AMNEZIAWG_PEER_FLAG` - bitwise flags for peers.

These values may be or'd together.

|Name|Description|
|--|--|
|`AMNEZIAWG_PEER_HAS_PUBLIC_KEY`|The PublicKey field is set.|
|`AMNEZIAWG_PEER_HAS_PRESHARED_KEY`|The PresharedKey field is set.|
|`AMNEZIAWG_PEER_HAS_PERSISTENT_KEEPALIVE`|The PersistentKeepAlive field is set.|
|`AMNEZIAWG_PEER_HAS_ENDPOINT`|The Endpoint field is set.|
|`AMNEZIAWG_PEER_REPLACE_ALLOWED_IPS`|Remove all allowed IPs before adding new ones (unused on get).|
|`AMNEZIAWG_PEER_REMOVE`|Remove specified peer (unused on get).|
|`AMNEZIAWG_PEER_UPDATE_ONLY`|Do not add a new peer (unused on get).|

### Enumeration: `AMNEZIAWG_ALLOWED_IP_FLAG` - bitwise flags for allowed IPs.

These values may be or'd together.

|Name|Description|
|--|--|
|`AMNEZIAWG_ALLOWED_IP_REMOVE`|Remove the specified allowed IP instead of adding it to the peer.|


### Function: `AmneziaWGSetConfiguration` - sets configuration of adapter.

```c
BOOL AmneziaWGSetConfiguration(AMNEZIAWG_ADAPTER_HANDLE Adapter, const AMNEZIAWG_INTERFACE *Config, DWORD Bytes);
```

Typedef'd as `AMNEZIAWG_SET_CONFIGURATION`.  Sets the configuration of the specified adapter. The `Config` argument represents a `AMNEZIAWG_INTERFACE` structure, immediately followed in memory by zero or more `AMNEZIAWG_PEER` or `AMNEZIAWG_ALLOWED_IP` structures. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`AMNEZIAWG_INTERFACE *`|Config|Adapter configuration.|
|`DWORD`|Bytes|Number of bytes of `Config` allocation.|


### Function: `AmneziaWGGetConfiguration` - gets configuration of adapter.

```c
BOOL AmneziaWGGetConfiguration(AMNEZIAWG_ADAPTER_HANDLE Adapter, AMNEZIAWG_INTERFACE *Config, DWORD *Bytes);
```

Typedef'd as `AMNEZIAWG_GET_CONFIGURATION`.  Gets the configuration of the specified adapter. The `Config` argument represents an `AMNEZIAWG_INTERFACE` structure, immediately followed in memory by zero or more `AMNEZIAWG_PEER` or `AMNEZIAWG_ALLOWED_IP` structures. Returns `TRUE` if successful, or returns `FALSE` if not and sets LastError. If LastError is `ERROR_MORE_DATA`, `Bytes` is updated with the number of bytes needed for successful operation. Since that byte value can change, this function should be called in a tight loop until success or until the error is not `ERROR_MORE_DATA`.

#### Parameters
|Type|Name|Description|
|--|--|--|
|`AMNEZIAWG_ADAPTER_HANDLE`|Adapter|Adapter handle obtained with `AmneziaWGCreateAdapter` or `AmneziaWGOpenAdapter`.|
|`AMNEZIAWG_INTERFACE *` (out)|Config|Adapter configuration.|
|`DWORD *` (in/out)|Bytes|Pointer to number of bytes of `Config` allocation, on input, and is updated when the function returns to the amount of bytes required.|

## Building

**Do not distribute drivers or files named "AmneziaWG" or "amneziawg" or similar, as they will most certainly clash with official deployments. Instead distribute `amneziawg.dll` as downloaded from the amneziawg-nt download server.**

General requirements:

- [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) with Windows SDK
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

`amneziawg-nt.sln` may be opened in Visual Studio for development and building. Be sure to run `bcdedit /set testsigning on` and then reboot before to enable unsigned driver loading. The default run sequence (F5) in Visual Studio will build the example project and its dependencies.

## License

The entire contents of this repository, including all documentation and example code, is "Copyright © 2018-2026 WireGuard LLC. All Rights Reserved." Source code is licensed under the [GPLv2](COPYING). Prebuilt binaries from the amneziawg-nt download server are released under a more permissive license suitable for more forms of software contained inside of the .zip files distributed there.

"""
Pydantic models for all IPC messages in the discovery module.

Message directions:
  Scanner  → Server : ScannerMessage / ScannerMessageAdapter
  Client   → Server : ClientMessage  / ClientMessageAdapter
  Both     → Server : AnnounceMessage / AnnounceMessageAdapter  (announce only)
  Server   → Scanner: ServerToScannerMessage / ServerToScannerMessageAdapter
  Server   → Client : StatusResponse + broadcast models (no union needed; always typed at call site)
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


# ─── Shared building blocks ───────────────────────────────────────────────────

class ParameterUpdate(BaseModel):
    name: str
    value: Any


class ScanResultItem(BaseModel):
    key: str
    result: dict[str, Any]


# ─── Scanner → Server ─────────────────────────────────────────────────────────

class ScannerAnnounce(BaseModel):
    command: Literal["announce"] = "announce"
    type: Literal["scanner"] = "scanner"
    name: str
    interfaces: list[str]
    parameters: dict[str, Any]


class ScannerAvailableInterfacesChanged(BaseModel):
    command: Literal["available_interfaces_changed"] = "available_interfaces_changed"
    interfaces: list[str]


class ScannerActiveInterfacesChanged(BaseModel):
    command: Literal["active_interfaces_changed"] = "active_interfaces_changed"
    interfaces: list[str]


class ScannerParametersChanged(BaseModel):
    command: Literal["parameters_changed"] = "parameters_changed"
    parameters: list[ParameterUpdate]


class ScannerResultsUpdate(BaseModel):
    command: Literal["scan_results_update"] = "scan_results_update"
    results: list[ScanResultItem]


class ScannerResultsRemove(BaseModel):
    command: Literal["scan_results_remove"] = "scan_results_remove"
    keys: list[str]


ScannerMessage = Annotated[
    Union[
        ScannerAnnounce,
        ScannerAvailableInterfacesChanged,
        ScannerActiveInterfacesChanged,
        ScannerParametersChanged,
        ScannerResultsUpdate,
        ScannerResultsRemove,
    ],
    Field(discriminator="command"),
]
ScannerMessageAdapter: TypeAdapter[ScannerMessage] = TypeAdapter(ScannerMessage)


# ─── Client → Server ──────────────────────────────────────────────────────────

class ClientAnnounce(BaseModel):
    command: Literal["announce"] = "announce"
    type: Literal["client"] = "client"
    unimportant: bool = False


class ClientSetActiveInterfaces(BaseModel):
    command: Literal["set_active_interfaces"] = "set_active_interfaces"
    scanner: str
    interfaces: list[str]


class ClientSetScannerParameters(BaseModel):
    command: Literal["set_scanner_parameters"] = "set_scanner_parameters"
    scanner: str
    parameters: list[ParameterUpdate]


class ClientClearCache(BaseModel):
    command: Literal["clear_cache"] = "clear_cache"
    scanners: list[str]


class ClientStopScanner(BaseModel):
    command: Literal["stop_scanner"] = "stop_scanner"
    scanner: str


class ClientStartBuiltinScanner(BaseModel):
    command: Literal["start_builtin_scanner"] = "start_builtin_scanner"
    scanner: str


class ClientGetBuiltinScanners(BaseModel):
    command: Literal["get_builtin_scanners"] = "get_builtin_scanners"


class ClientGetRegisteredScanners(BaseModel):
    command: Literal["get_registered_scanners"] = "get_registered_scanners"


class ClientGetRegisteredScanner(BaseModel):
    command: Literal["get_registered_scanner"] = "get_registered_scanner"
    scanner: str


class ClientGetScannerAvailableInterfaces(BaseModel):
    command: Literal["get_scanner_available_interfaces"] = "get_scanner_available_interfaces"
    scanner: str


class ClientGetScannerActiveInterfaces(BaseModel):
    command: Literal["get_scanner_active_interfaces"] = "get_scanner_active_interfaces"
    scanner: str


class ClientGetScannerParameters(BaseModel):
    command: Literal["get_scanner_parameters"] = "get_scanner_parameters"
    scanner: str


class ClientGetResults(BaseModel):
    command: Literal["get_results"] = "get_results"
    scanner: str


class ClientGetResult(BaseModel):
    command: Literal["get_result"] = "get_result"
    scanner: str
    key: str


ClientMessage = Annotated[
    Union[
        ClientSetActiveInterfaces,
        ClientSetScannerParameters,
        ClientClearCache,
        ClientStopScanner,
        ClientStartBuiltinScanner,
        ClientGetBuiltinScanners,
        ClientGetRegisteredScanners,
        ClientGetRegisteredScanner,
        ClientGetScannerAvailableInterfaces,
        ClientGetScannerActiveInterfaces,
        ClientGetScannerParameters,
        ClientGetResults,
        ClientGetResult,
    ],
    Field(discriminator="command"),
]
ClientMessageAdapter: TypeAdapter[ClientMessage] = TypeAdapter(ClientMessage)


# Both client and scanner use command="announce"; discriminate on "type".
AnnounceMessage = Annotated[
    Union[ClientAnnounce, ScannerAnnounce],
    Field(discriminator="type"),
]
AnnounceMessageAdapter: TypeAdapter[AnnounceMessage] = TypeAdapter(AnnounceMessage)


# ─── Server → Client ──────────────────────────────────────────────────────────

class StatusResponse(BaseModel):
    """
    Response sent by the server to acknowledge a command.
    extra="allow" lets callers attach response-specific fields (e.g. scanners=,
    interfaces=, results=) without needing a separate model per query type.
    Those extras are included in model_dump() output.
    """
    model_config = ConfigDict(extra="allow")

    command: Literal["status"] = "status"
    status: Literal["accepted", "rejected"]
    reason: Optional[str] = None


class ServerAvailableScannersChanged(BaseModel):
    command: Literal["available_scanners_changed"] = "available_scanners_changed"
    scanners: list[str]


class ServerAvailableInterfacesChanged(BaseModel):
    command: Literal["available_interfaces_changed"] = "available_interfaces_changed"
    scanner: str
    interfaces: list[str]


class ServerActiveInterfacesChanged(BaseModel):
    command: Literal["active_interfaces_changed"] = "active_interfaces_changed"
    scanner: str
    interfaces: list[str]


class ServerParametersChanged(BaseModel):
    command: Literal["parameters_changed"] = "parameters_changed"
    scanner: str
    parameters: list[ParameterUpdate]


class ServerResultsUpdate(BaseModel):
    command: Literal["scan_results_update"] = "scan_results_update"
    scanner: str
    results: list[ScanResultItem]


class ServerResultsRemove(BaseModel):
    command: Literal["scan_results_remove"] = "scan_results_remove"
    scanner: str
    keys: list[str]


ServerToClientMessage = Annotated[
    Union[
        StatusResponse,
        ServerAvailableScannersChanged,
        ServerAvailableInterfacesChanged,
        ServerActiveInterfacesChanged,
        ServerParametersChanged,
        ServerResultsUpdate,
        ServerResultsRemove,
    ],
    Field(discriminator="command"),
]
ServerToClientMessageAdapter: TypeAdapter[ServerToClientMessage] = TypeAdapter(ServerToClientMessage)


# ─── Server → Scanner ─────────────────────────────────────────────────────────

class ServerSetActiveInterfaces(BaseModel):
    command: Literal["set_active_interfaces"] = "set_active_interfaces"
    interfaces: list[str]


class ServerSetScannerParameters(BaseModel):
    command: Literal["set_scanner_parameters"] = "set_scanner_parameters"
    parameters: list[ParameterUpdate]


class ServerClearCache(BaseModel):
    command: Literal["clear_cache"] = "clear_cache"


class ServerStopScanner(BaseModel):
    command: Literal["stop_scanner"] = "stop_scanner"


# StatusResponse is included so scanners can recognise server acknowledgements
# (e.g. responses to scan_results_update) without spurious unknown-command warnings.
ServerToScannerMessage = Annotated[
    Union[
        ServerSetActiveInterfaces,
        ServerSetScannerParameters,
        ServerClearCache,
        ServerStopScanner,
        StatusResponse,
    ],
    Field(discriminator="command"),
]
ServerToScannerMessageAdapter: TypeAdapter[ServerToScannerMessage] = TypeAdapter(ServerToScannerMessage)



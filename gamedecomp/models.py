"""JSON-compatible evidence artifacts shared by all backends."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str


@dataclass
class Function:
    id: str
    name: str
    address: int
    instructions: list[Instruction] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    source: str | None = None
    diagnostics: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict) -> "Function":
        data = dict(value)
        data['instructions'] = [Instruction(**item) for item in data.get('instructions', [])]
        return cls(**data)


@dataclass
class Analysis:
    binary_hash: str
    format: str
    architecture: str
    backend: str
    functions: list[Function] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "Analysis":
        data = dict(value)
        data['functions'] = [Function.from_dict(item) for item in data.get('functions', [])]
        return cls(**data)

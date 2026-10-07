from dataclasses import dataclass, asdict
import base64
import ipaddress


@dataclass(frozen=True)
class RouterCAEntry:
    id: int
    prefix: str
    label: str
    public_key: str | None = None
    endpoint: str | None = None
    encryption_public_key: str | None = None

    def validate(self):
        ipaddress.ip_network(self.prefix, strict=False)
        if not 1 <= self.id <= 65535:
            raise ValueError("Router-CA id must be 1..65535")
        if not self.label or any(c.isspace() for c in self.label):
            raise ValueError("invalid label")
        if self.public_key is not None:
            try:
                key = base64.b64decode(self.public_key, validate=True)
            except Exception as exc:
                raise ValueError("Router-CA public key must be base64") from exc
            if len(key) != 32:
                raise ValueError("Router-CA public key must be 32 bytes")
        if self.encryption_public_key is not None:
            try:
                from nlsxnetos.nls.rsa import load_public_key
                load_public_key(self.encryption_public_key)
            except ValueError as exc:
                raise ValueError("Router-CA RSA encryption public key is invalid") from exc
        if self.endpoint is not None:
            from nlsxnetos.nls.config import endpoint
            endpoint(self.endpoint)

    @property
    def nls_ready(self) -> bool:
        return bool(self.public_key and self.endpoint and self.encryption_public_key)

    def as_dict(self):
        return asdict(self)

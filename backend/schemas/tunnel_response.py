from datetime import datetime

from pydantic import BaseModel


class TunnelCommandResponse(BaseModel):
    success: bool
    node: str
    mode: str
    command: str
    output: str
    timestamp: datetime

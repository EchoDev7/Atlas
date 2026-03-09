from pydantic import BaseModel, Field


class TunnelCommandRequest(BaseModel):
    command: str = Field(..., min_length=1, max_length=2048)

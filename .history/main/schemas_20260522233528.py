from pydantic import BaseModel, Field


class PipelineRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Target URL or domain")
    mode: str = Field(default="c", description="Pipeline mode: quick or deep")


class RefreshRequest(BaseModel):
    force: bool = Field(default=True, description="Rebuild child images")


class StopRequest(BaseModel):
    reason: str | None = Field(default=None, description="Optional stop reason")

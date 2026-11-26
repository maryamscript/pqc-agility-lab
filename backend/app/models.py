
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    filename: str = Field(
        default="submitted.py",
        max_length=255
    )

    source_code: str = Field(
        min_length=1,
        max_length=100000
    )

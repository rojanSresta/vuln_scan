"""Custom HTTP exceptions"""

from fastapi import HTTPException


class ScanNotFoundError(HTTPException):
    """Scan not found error"""

    def __init__(self):
        super().__init__(status_code=404, detail="Scan not found")


class InvalidURLError(HTTPException):
    """Invalid URL error"""

    def __init__(self):
        super().__init__(status_code=400, detail="Invalid target URL")


class ScanFailedError(HTTPException):
    """Scan failed error"""

    def __init__(self, message: str = "Scan failed"):
        super().__init__(status_code=500, detail=message)

from fastapi import HTTPException


class UnauthorizedError(Exception):
    def __init__(self, error_description: str):
        super().__init__(error_description)


class EntryNotFound(HTTPException):
    def __init__(self, error_description: str):
        super().__init__(status_code=404, detail=error_description)

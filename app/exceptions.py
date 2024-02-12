class UnauthorizedError(Exception):
    def __init__(self, error_description: str):
        super().__init__(error_description)


class EntryNotFound(Exception):
    def __init__(self, error_description: str):
        super().__init__(error_description)

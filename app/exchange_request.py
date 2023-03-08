from pydantic import BaseModel


class ExchangeRequest(BaseModel):
    exchange_token: str

import logging

from fastapi import APIRouter, Depends, Request

from app.dependencies import service_
from app.exchange_request import ExchangeRequest
from app.service import Service

router = APIRouter()


logger = logging.getLogger(__name__)


@router.post("/get-uzi-by-exchange")
def get_uzi_by_exchange(
    exchange_request: ExchangeRequest,
    request: Request,
    service: Service = Depends(lambda: service_),
):
    return service.handle_request(request, exchange_request)

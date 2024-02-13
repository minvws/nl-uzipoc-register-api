import logging
import time
import datetime

from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse, Response

from app.dependencies import request_handler_service_
from app.services.request_handler_service import RequestHandlerService

router = APIRouter()


logger = logging.getLogger(__name__)


@router.post("/get-uzi-by-exchange")
def get_uzi_by_exchange(
    request: Request,
    service: RequestHandlerService = Depends(lambda: request_handler_service_),
) -> Response:
    return service.handle_exchange_request(request)


@router.post("/get-uzi")
async def get_uzi_by_digid_artifact(
    request: Request,
    service: RequestHandlerService = Depends(lambda: request_handler_service_),
) -> Response:
    return await service.handle_saml_request(request)


@router.get("/signed-uzi")
async def get_signed_uzi(
    uzi_number: str,
    service: RequestHandlerService = Depends(lambda: request_handler_service_),
) -> Response:
    signed_uzi_number = service.get_signed_uzi_number(uzi_number)
    return JSONResponse({"signed_uzi_number": signed_uzi_number})

@router.get("/signed-bsn")
async def get_signed_bsn(
        bsn_number: str,
        service: RequestHandlerService = Depends(lambda: request_handler_service_)
) -> Response:
    signed_bsn = service.get_signed_userinfo_token(bsn_number)
    return JSONResponse({"signed_bsn_number": signed_bsn})

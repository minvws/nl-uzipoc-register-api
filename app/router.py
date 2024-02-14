import logging

from fastapi import APIRouter, Depends
from fastapi.exceptions import HTTPException
from starlette.responses import JSONResponse, Response
from starlette.requests import Request

from app.dependencies import request_handler_service_
from app.services.request_handler_service import RequestHandlerService
from app.exceptions import EntryNotFound

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


@router.get("/signed-userinfo")
async def get_signed_userinfo(
    bsn: str,
    service: RequestHandlerService = Depends(lambda: request_handler_service_),
) -> Response:
    signed_userinfo = service.get_signed_userinfo_token(bsn)
    return JSONResponse({"signed_userinfo": signed_userinfo})

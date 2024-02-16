import logging
from typing import Optional

from fastapi import APIRouter, Depends
from starlette.responses import JSONResponse, Response
from starlette.requests import Request

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


@router.get("/signed-userinfo")
async def get_signed_userinfo(
    bsn: str,
    jwt_exp_offset: Optional[int] = None,
    service: RequestHandlerService = Depends(lambda: request_handler_service_),
) -> Response:
    signed_userinfo = service.get_signed_userinfo_token(bsn, jwt_exp_offset)
    return JSONResponse({"signed_userinfo": signed_userinfo})

import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import JSONResponse, Response

from app.dependencies import register_service_, request_handler_service_
from app.services.register_service import RegisterService
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
    service: RegisterService = Depends(lambda: register_service_),
) -> Response:
    return await service.handle_saml_request(request)


@router.get("/signed-uzi")
async def get_signed_uzi(
    uzi_number: str,
    service: RegisterService = Depends(lambda: register_service_),
) -> Response:
    signed_uzi_number = service.get_signed_uzi_number(uzi_number)
    return JSONResponse({"signed_uzi_number": signed_uzi_number})

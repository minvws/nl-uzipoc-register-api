import logging

from fastapi import APIRouter, Depends, Request

from app.dependencies import service_
from app.service import Service

router = APIRouter()


logger = logging.getLogger(__name__)


@router.post("/get-uzi-by-exchange")
def get_uzi_by_exchange(
    request: Request,
    service: Service = Depends(lambda: service_),
):
    return service.handle_exchange_request(request)


@router.post("/get-uzi")
async def get_uzi_by_digid_artifact(
    request: Request,
    service: Service = Depends(lambda: service_),
):
    return await service.handle_saml_request(request)

import logging

from fastapi import APIRouter, Depends, Request, HTTPException
from starlette.responses import JSONResponse

from app.dependencies import service_, zsm_feature_
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


@router.get("/signed-uzi")
async def get_signed_uzi(
    uzi_number: str,
    service: Service = Depends(lambda: service_),
    zsm_feature: bool = Depends(lambda: zsm_feature_),
):
    if zsm_feature:
        return JSONResponse(
            {"signed_uzi_number": service.get_signed_uzi_number(uzi_number)}
        )
    raise HTTPException(status_code=404, detail="Not found")

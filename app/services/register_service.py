import logging
from typing import List, Union, Optional

from app.models.identity import Identity

logger = logging.getLogger(__name__)


class RegisterService:
    def __init__(
        self,
        register: List[Identity],
    ):
        self._register = register

    def get_claims_from_register_by_bsn(
        self, bsn: str, token: Union[str, None] = None
    ) -> Optional[Identity]:
        return self._get_claims_from_register("bsn", bsn, token)

    def get_claims_from_register_by_uzi(
        self, uzi: Union[str, None], token: Union[str, None] = None
    ) -> Optional[Identity]:
        return self._get_claims_from_register("uzi_id", uzi, token)

    def _get_claims_from_register(
        self, key: str, value: Union[str, None], token: Union[str, None] = None
    ) -> Optional[Identity]:
        for identity in self._register:
            if identity[key] == value:
                if token is None or identity["token"] == token:
                    return identity
        return None

from typing import List, Optional, Any, Dict
from app.models.relation import Relation


class Identity:
    """
    Represents an identity for a user in the Register.
    """

    def __init__(
        self,
        bsn: str,
        loa_uzi: str,
        loa_authn: str,
        token: str,
        uzi_id: str,
        initials: Optional[str],
        surname_prefix: Optional[str],
        surname: Optional[str],
        relations: List[Relation],
    ):
        self._bsn = bsn
        self._loa_uzi = loa_uzi
        self._loa_authn = loa_authn
        self._token = token
        self._uzi_id = uzi_id
        self._initials = initials
        self._surname_prefix = surname_prefix
        self._surname = surname
        self._relations = relations

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    @property
    def bsn(self) -> str:
        return self._bsn

    @bsn.setter
    def bsn(self, bsn: str) -> None:
        self._bsn = bsn

    @property
    def loa_uzi(self) -> str:
        return self._loa_uzi

    @loa_uzi.setter
    def loa_uzi(self, loa_uzi: str) -> None:
        self._loa_uzi = loa_uzi

    @property
    def loa_authn(self) -> str:
        return self._loa_authn

    @loa_authn.setter
    def loa_authn(self, loa_authn: str) -> None:
        self._loa_authn = loa_authn

    @property
    def token(self) -> str:
        return self._token

    @token.setter
    def token(self, token: str) -> None:
        self._token = token

    @property
    def uzi_id(self) -> str:
        return self._uzi_id

    @uzi_id.setter
    def uzi_id(self, uzi_id: str) -> None:
        self._uzi_id = uzi_id

    @property
    def initials(self) -> Optional[str]:
        return self._initials

    @initials.setter
    def initials(self, initials: str) -> None:
        self._initials = initials

    @property
    def surname_prefix(self) -> Optional[str]:
        return self._surname_prefix

    @surname_prefix.setter
    def surname_prefix(self, surname_prefix: str) -> None:
        self._surname_prefix = surname_prefix

    @property
    def surname(self) -> Optional[str]:
        return self._surname

    @surname.setter
    def surname(self, surname: str) -> None:
        self._surname = surname

    @property
    def relations(self) -> List[Relation]:
        return self._relations

    @relations.setter
    def relations(self, args: dict) -> None:
        if isinstance(args, Relation):
            self._relations.append(args)
        else:
            new_relation = Relation(**args)
            self._relations.append(new_relation)
        raise TypeError("Invalid Type relation")

    def to_dict(self, allowed_uras: Optional[List[str]] = None) -> Dict[str, Any]:
        identity_as_dict = {
            "bsn": self.bsn,
            "loa_uzi": self.loa_uzi,
            "loa_authn": self.loa_authn,
            "token": self.token,
            "uzi_id": self.uzi_id,
            "initials": self.initials,
            "surname_prefix": self.surname_prefix,
            "surname": self.surname,
            "relations": [x.to_dict() for x in self.relations],
        }

        if allowed_uras is not None:
            relations = self.filter_relations(allowed_uras)
            identity_as_dict["relations"] = relations
            return identity_as_dict

        return identity_as_dict

    def filter_relations(self, allowed_uras: List[str]) -> List[Dict[str, Any]]:
        """
        matches any of the allowed uras in the relation attribute and returns them
        :param allowed_uras: List[str]
        :return: List[Dict[str, Any]]
        """
        if "*" in allowed_uras:
            return [r.to_dict() for r in self.relations]
        return [r.to_dict() for r in self.relations if r.ura not in allowed_uras]

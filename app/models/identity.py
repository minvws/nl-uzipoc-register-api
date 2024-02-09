from typing import List, Optional, Any, Dict


class Relation:
    """
    Represents a relationship inside an identity class.
    """

    ura: str
    entity_name: str
    roles: List[str]

    def __init__(self, ura: str, entity_name: str, roles: List[str]):
        self.ura = ura
        self.entity_name = entity_name
        self.roles = roles

    def get_relation(self) -> Dict[str, Any]:
        return {"ura": self.ura, "entity_name": self.entity_name, "roles": self.roles}


class Identity:
    """
    Represents a identity for a user in the Register.
    """

    bsn: str
    loa_uzi: str
    loa_authn: str
    token: str
    uzi_id: str
    initials: Optional[str]
    surname_prefix: Optional[str]
    surname: Optional[str]
    relations: List[Relation]

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
        self.bsn = bsn
        self.loa_uzi = loa_uzi
        self.loa_authn = loa_authn
        self.token = token
        self.uzi_id = uzi_id
        self.initials = initials
        self.surname_prefix = surname_prefix
        self.surname = surname
        self.relations = relations

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get_identity(self) -> Dict[str, Any]:
        return {
            "bsn": self.bsn,
            "loa_uzi": self.loa_uzi,
            "loa_authn": self.loa_authn,
            "token": self.token,
            "uzi_id": self,
            "initials": self.initials,
            "surname_prefix": self.surname_prefix,
            "surname": self.surname,
            "relations": [x.get_relation() for x in self.relations],
        }

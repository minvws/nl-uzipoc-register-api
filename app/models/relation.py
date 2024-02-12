from typing import List, Dict, Any


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

    def to_dict(self) -> Dict[str, Any]:
        return {"ura": self.ura, "entity_name": self.entity_name, "roles": self.roles}

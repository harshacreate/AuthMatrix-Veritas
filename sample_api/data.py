"""Shared, in-memory data layer and a trivial token scheme.

The token is intentionally simple (base64 of the username) so the focus stays on
*authorization* logic, not auth cryptography. Each app gets a fresh copy of the
seed data via `fresh_store()` so tests are isolated.

The model is multi-dimensional on purpose, so authorization can be exercised
across users, roles, tenants, resources and object properties:

  roles   : user  < manager (tenant-scoped admin)  < admin (global)
  tenants : acme, globex
  objects : user profiles (with sensitive ssn/salary), orders, tenant documents
"""

from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional

ROLES = ("user", "manager", "admin")
TENANTS = ("acme", "globex")


@dataclass
class User:
    id: int
    username: str
    role: str                     # "user" | "manager" | "admin"
    tenant: str                   # "acme" | "globex"
    email: str
    ssn: str                      # sensitive; must never leak cross-user
    salary: int                   # sensitive; must never leak cross-user


@dataclass
class Order:
    id: int
    owner_id: int
    item: str
    amount: int


@dataclass
class Document:
    id: int
    tenant: str
    title: str
    body: str


@dataclass
class Store:
    users: Dict[int, User] = field(default_factory=dict)
    orders: Dict[int, Order] = field(default_factory=dict)
    documents: Dict[int, Document] = field(default_factory=dict)

    def user_by_name(self, username: str) -> Optional[User]:
        for u in self.users.values():
            if u.username == username:
                return u
        return None

    def orders_for(self, owner_id: int) -> List[Order]:
        return [o for o in self.orders.values() if o.owner_id == owner_id]

    def documents_for(self, tenant: str) -> List[Document]:
        return [d for d in self.documents.values() if d.tenant == tenant]


_SEED = Store(
    users={
        1: User(1, "alice", "user", "acme", "alice@acme.example", "111-11-1111", 90000),
        2: User(2, "bob", "user", "acme", "bob@acme.example", "222-22-2222", 70000),
        3: User(3, "carol", "user", "globex", "carol@globex.example", "333-33-3333", 85000),
        4: User(4, "mallory", "manager", "globex", "mallory@globex.example", "444-44-4444", 120000),
        9: User(9, "admin", "admin", "acme", "admin@acme.example", "999-99-9999", 150000),
    },
    orders={
        101: Order(101, 1, "Keyboard", 80),
        102: Order(102, 1, "Monitor", 300),
        201: Order(201, 2, "Mouse", 25),
        301: Order(301, 3, "Webcam", 60),
    },
    documents={
        1001: Document(1001, "acme", "Acme Q3 Strategy", "Acme confidential strategy."),
        1002: Document(1002, "acme", "Acme Payroll", "Acme salary bands."),
        2001: Document(2001, "globex", "Globex Roadmap", "Globex confidential roadmap."),
    },
)

# Convenience catalogues for the workbench UI.
USERNAMES = ["alice", "bob", "carol", "mallory", "admin"]


def fresh_store() -> Store:
    return deepcopy(_SEED)


def make_token(username: str) -> str:
    return base64.urlsafe_b64encode(username.encode()).decode()


def read_token(token: str) -> Optional[str]:
    try:
        return base64.urlsafe_b64decode(token.encode()).decode()
    except Exception:
        return None

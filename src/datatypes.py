from dataclasses import dataclass


@dataclass
class User:
    id: int
    name: str
    passhash: str
    created: int


@dataclass
class Message:
    id: int
    sender_id: int
    receiver_id: int
    body: str
    ts: int  # unix timestamp (seconds)

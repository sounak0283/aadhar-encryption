"""Shared slowapi Limiter instance — imported by main.py and routers alike."""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

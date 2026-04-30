"""DNS mutation strategies package."""

from .base import BaseMutationStrategy
from .basic import *
from .header import *
from .record import *
from .logical import *

__all__ = [
    "BaseMutationStrategy",
]
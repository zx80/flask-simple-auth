from typing import Any
from FlaskSimpleAuth import Reference

import logging
log = logging.getLogger("shared")

something: Any = Reference()

def init_app(**config):
    log.info(f"initializing with {config}")
    something._setobj(config.get("something", "SOMETHING!"))

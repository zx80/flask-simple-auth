from typing import Any
from FlaskSimpleAuth import Reference

import logging
log = logging.getLogger("shared")

something: Any = Reference(set_name="set_object")

def init_app(**config):
    log.info(f"initializing with {config}")
    something.set_object(config.get("something", "SOMETHING!"))

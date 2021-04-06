from typing import Any
from FlaskSimpleAuth import Reference

import logging
log = logging.getLogger("shared")

something: Any = Reference(set_name="set_object")
hello_world: Any = Reference()

def init_app(**config):
    log.info(f"initializing with {config}")
    val = config.get("something", "SOMETHING!")
    something.set_object(val)
    hello_world.set("hello world!")

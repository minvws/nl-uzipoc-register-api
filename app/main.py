import configparser
import logging

import uvicorn
from fastapi import FastAPI

from app.router import router


def run_app():
    config = configparser.ConfigParser()
    config.read("app.conf")

    loglevel = logging.getLevelName(
        config.get("app", "loglevel", fallback="debug").upper()
    )
    if isinstance(loglevel, str):
        raise ValueError(f"Invalid loglevel {loglevel.upper()}")
    logging.basicConfig(
        level=loglevel,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )
    fastapi = FastAPI()
    fastapi.include_router(router)
    return fastapi


def kwargs_from_config():
    config = configparser.ConfigParser()
    config.read("app.conf")
    kwargs = {
        "host": config.get("uvicorn", "host"),
        "port": config.getint("uvicorn", "port"),
        "reload": config.getboolean("uvicorn", "reload"),
        "proxy_headers": True,
        "workers": config.getint("uvicorn", "workers"),
    }
    if config.getboolean("uvicorn", "use_ssl"):
        kwargs["ssl_keyfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "key_file")
        )
        kwargs["ssl_certfile"] = (
            config.get("uvicorn", "base_dir") + "/" + config.get("uvicorn", "cert_file")
        )
    return kwargs


if __name__ == "__main__":
    uvicorn.run("app.main:run_app", **kwargs_from_config())

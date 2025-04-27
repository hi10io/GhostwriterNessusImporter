from lib.settings.cli import get_options
from lib.types.namespace import Namespace
from lib.utils.banner import print_banner
from lib.utils.settings import parse_exclude_hosts
from pathlib import Path

SETTINGS_PATH = Path("settings.ini")
DEFAULT_SETTINGS_PATH = Path(__file__).parent.absolute() / Path("settings-default.ini")


def load_settings():

    settings = Namespace.from_ini_file(SETTINGS_PATH, extended_interpolation=True)
    if settings.get("nessus"):
        parse_exclude_hosts(settings)

    __default_settings = Namespace.from_ini_file(
        DEFAULT_SETTINGS_PATH, extended_interpolation=True
    )
    if __default_settings.get("nessus"):
        parse_exclude_hosts(__default_settings)
    settings.baseline(__default_settings)

    options = get_options()
    if options.get("nessus"):
        parse_exclude_hosts(options)
    options.baseline(settings, exceptions="*")
    return options


#print_banner()


print(__name__)
settings = load_settings()

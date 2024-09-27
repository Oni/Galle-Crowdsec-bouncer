import sys
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import pathlib
import configparser
import logging
import time
import requests

from pycrowdsec.client import StreamClient

LOG = logging.getLogger(__name__)


def main() -> int:
    parser = ArgumentParser(
        description=__doc__, formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "config",
        metavar="<config file>",
        type=pathlib.Path,
        nargs=1,
        help="the location of the *.ini config file",
    )
    args = parser.parse_args()

    config_path = args.config[0]
    if not config_path.is_file():
        LOG.error(f"Unable to locate {config_path}")
        return 1

    config = configparser.ConfigParser()
    config.read(config_path)

    try:
        log_level_s = config.get("general", "log_level")
    except configparser.NoSectionError:
        LOG.error("Invalid config file: no [general] section")
        return 1
    except configparser.NoOptionError:
        LOG.error("Invalid config file: no 'log_level' option in [general] section")
        return 1

    try:
        log_level = {
            "error": logging.ERROR,
            "warn": logging.WARN,
            "info": logging.INFO,
            "debug": logging.DEBUG,
        }[log_level_s]
    except KeyError:
        LOG.error(
            "Invalid config file: 'log_level' option in [general] section must be 'error', "
            "'warn', 'info' or 'debug'"
        )
        return 1

    logging.basicConfig(level=log_level, format="%(asctime)-15s %(name)s %(message)s")

    try:
        crowdsec_api_key = config.get("general", "crowdsec_api_key")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        LOG.error(
            "Invalid config file: no 'crowdsec_api_key' option in [general] section"
        )
        return 1

    try:
        crowdsec_lapi_url = config.get("general", "crowdsec_lapi_url")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        LOG.error(
            "Invalid config file: no 'crowdsec_lapi_url' option in [general] section"
        )
        return 1

    try:
        galle_control_url = config.get("general", "galle_control_url")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        LOG.error(
            "Invalid config file: no 'galle_control_url' option in [general] section"
        )
        return 1

    try:
        poll_interval_s = config.get("general", "poll_interval")
        # configparser.NoSectionError eventually raised by previous option query
    except configparser.NoOptionError:
        LOG.error("Invalid config file: no 'poll_interval' option in [general] section")
        return 1
    try:
        poll_interval = int(poll_interval_s)
    except ValueError:
        LOG.error("Invalid config file: the 'poll_interval' must be an int")
        return 1
    if poll_interval <= 0:
        raise ValueError(
            "Invalid config file: the 'poll_interval' must be higher than 0"
        )

    LOG.info("Starting bouncer")

    try:
        client = StreamClient(
            api_key=crowdsec_api_key, lapi_url=crowdsec_lapi_url, interval=poll_interval
        )
    except requests.exceptions.HTTPError:
        LOG.error("Connection to crowdsec forbidden: API key no accepted")
        return 1

    while True:
        try:
            client.run()
        except requests.exceptions.ConnectTimeout:
            LOG.error(
                "Could not reach crowdsec at '%s': retry in a few seconds",
                crowdsec_lapi_url,
            )
            time.sleep(20)
            continue
        else:
            LOG.info("Crowdsec connection successful")
            break

    while True:
        decisions = client.get_current_decisions()

        try:
            req = requests.post(
                galle_control_url,
                data={"verb": "ban_set", "ips": "-".join(decisions.keys())},
            )
        except requests.exceptions.ConnectionError:
            LOG.error("Could not connect to galle at '%s'", galle_control_url)
        else:
            if req.status_code == 200:
                LOG.info(
                    "Galle ban list successfully updated with %s decisions",
                    len(decisions),
                )
            else:
                LOG.error(
                    "Galle ban list update failed with code '%s'", req.status_code
                )
        time.sleep(poll_interval)


if __name__ == "__main__":
    sys.exit(main())

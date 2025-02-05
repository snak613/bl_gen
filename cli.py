import argparse
import asyncio
from pathlib import Path

from lib import load_config, process_blacklist

DEFAULT_CONFIG_DIR = "config/blacklist.toml"


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", "-c", help="path to config", type=Path, default=DEFAULT_CONFIG_DIR
    )
    parser.add_argument("--out", "-o", help="directory to store artifacts", type=Path)
    return parser.parse_args()


async def main():
    args = get_args()
    config = load_config(args.config)
    if args.out:
        config["general"]["out_dir"] = args.out
    await process_blacklist(config)


if __name__ == "__main__":
    asyncio.run(main())

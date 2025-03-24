import argparse
import asyncio
from pathlib import Path

from lib.ips import get_google_ips, get_isc_thread_category

DEFAULT_CONFIG_DIR = "config/default.toml"



async def main():
    import json
    ips = await get_google_ips()
    ip_ranges =  json.loads(ips)
    print(ip_ranges)

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
import argparse
import json


def set_path(data: dict, path: str, value: str) -> None:
    parts = path.split(".")
    current = data
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = value


def main() -> None:
    parser = argparse.ArgumentParser(description="Set a dotted JSON config value.")
    parser.add_argument("config")
    parser.add_argument("path", help="Example: collector.esp32_url")
    parser.add_argument("value")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    set_path(data, args.path, args.value)
    with open(args.config, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()


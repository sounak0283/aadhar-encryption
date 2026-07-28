"""
check_mongo.py
Quick connectivity check: confirms MONGO_URI in .env can actually reach the
configured database, and reports what collections exist there. Never prints
the connection string itself.

Usage:
    python scripts/check_mongo.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient  # noqa: E402
from pymongo.errors import PyMongoError  # noqa: E402

from app.config import get_mongo_db_name, get_mongo_uri  # noqa: E402


def main() -> None:
    db_name = get_mongo_db_name()
    print(f"Connecting to database {db_name!r}...")

    try:
        client = MongoClient(get_mongo_uri(), serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
    except PyMongoError as exc:
        print(f"FAILED to connect: {exc}")
        raise SystemExit(1)

    print("Connected successfully.")
    collections = client[db_name].list_collection_names()
    print(f"Existing collections in {db_name!r}: {collections or '(none yet)'}")

    expected = {"containers", "audit_log"}
    missing = expected - set(collections)
    if missing:
        print(
            f"Note: {sorted(missing)} don't exist yet — that's expected. "
            "They're created automatically the first time the app writes to them."
        )


if __name__ == "__main__":
    main()

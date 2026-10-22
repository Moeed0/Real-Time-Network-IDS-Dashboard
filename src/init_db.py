from ids.config import get_settings
from ids.db import connect_database
from ids.schema import ensure_schema


def main() -> None:
    settings = get_settings()
    conn = connect_database(settings.db_file)

    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    print("Database initialized successfully.")
    print("Alerts and packets tables are ready.")


if __name__ == "__main__":
    main()

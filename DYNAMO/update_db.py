from sqlalchemy import inspect, text
from storage.database import engine
from storage.models import Base


_STRING_TYPES = {
    "VARCHAR", "CHAR", "TEXT", "STRING",
    "CHARACTER VARYING", "CHARACTER",
}

_NUMERIC_TYPES = {
    "INTEGER", "INT", "BIGINT", "SMALLINT",
    "FLOAT", "REAL", "DOUBLE PRECISION", "NUMERIC", "DECIMAL",
}

_BOOL_TYPES = {"BOOLEAN", "BOOL"}

_TIME_TYPES = {
    "TIMESTAMP", "TIMESTAMP WITHOUT TIME ZONE",
    "TIMESTAMP WITH TIME ZONE", "DATE", "TIME",
}


def _default_for(col_type_name, column):
    if column.default is not None and getattr(column.default, "is_scalar", False):
        value = column.default.arg
        if isinstance(value, str):
            return f"DEFAULT '{value}'"
        if isinstance(value, bool):
            return f"DEFAULT {'TRUE' if value else 'FALSE'}"
        if isinstance(value, (int, float)):
            return f"DEFAULT {value}"
        return f"DEFAULT '{value}'"

    upper = col_type_name.upper()

    for t in _STRING_TYPES:
        if upper.startswith(t):
            return "DEFAULT ''"
    for t in _NUMERIC_TYPES:
        if upper.startswith(t):
            return "DEFAULT 0"
    for t in _BOOL_TYPES:
        if upper.startswith(t):
            return "DEFAULT FALSE"
    for t in _TIME_TYPES:
        if upper.startswith(t):
            return ""
    return ""


def upgrade_database_schema():
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    with engine.begin() as connection:
        Base.metadata.create_all(bind=connection)

        added = 0
        skipped = 0

        for table_name, table in Base.metadata.tables.items():
            if table_name not in existing_tables:
                continue

            db_columns = {c["name"] for c in inspector.get_columns(table_name)}

            for column in table.columns:
                if column.name in db_columns:
                    continue

                col_type = column.type.compile(engine.dialect)
                col_type_name = type(column.type).__name__

                default_clause = _default_for(col_type_name, column)

                if column.nullable:
                    nullability = ""
                elif default_clause:
                    nullability = "NOT NULL"
                else:
                    nullability = ""
                    print(f"[~] Skipping {table_name}.{column.name} — "
                          f"non-nullable {col_type_name} with no safe default")

                if not column.nullable and not default_clause:
                    skipped += 1
                    continue

                sql = (f"ALTER TABLE {table_name} ADD COLUMN "
                       f"{column.name} {col_type} {nullability} "
                       f"{default_clause}").strip() + ";"

                try:
                    print(f"[+] Adding {table_name}.{column.name} ({col_type})")
                    connection.execute(text(sql))
                    added += 1
                except Exception as e:
                    print(f"[!] Failed to add {table_name}.{column.name}: {e}")
                    skipped += 1

        print(f"[+] Done. {added} column(s) added, {skipped} skipped.")


if __name__ == "__main__":
    print("[*] Syncing DB schema…")
    upgrade_database_schema()
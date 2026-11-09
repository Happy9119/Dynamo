from datetime import datetime

DATE_FMT = "%d-%m-%Y"
TIME_FMT = "%H:%M:%S"
DT_FMT   = "%d-%m-%Y %H:%M:%S"


def now() -> datetime:
    return datetime.now()


def fmt_date(dt) -> str:
    return dt.strftime(DATE_FMT) if dt else ""


def fmt_time(dt) -> str:
    return dt.strftime(TIME_FMT) if dt else ""


def fmt_dt(dt) -> str:
    return dt.strftime(DT_FMT) if dt else ""


def parse_dt(s: str):
    if not s:
        return None
    try:
        return datetime.strptime(s, DT_FMT)
    except ValueError:
        return None
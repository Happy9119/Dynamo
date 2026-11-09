import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEFAULT_TRIAGE = os.environ.get("TRIAGE_MODEL", "phi3:mini")
DEFAULT_DEEP = os.environ.get("DEEP_MODEL", "mistral")


def _read_setting(key):
    try:
        from storage.database import SessionLocal
        from storage.models import SettingsModel
    except Exception:
        return None
    session = SessionLocal()
    try:
        row = session.query(SettingsModel).filter_by(key=key).first()
        return row.value if row and row.value else None
    except Exception:
        return None
    finally:
        session.close()


def _write_setting(key, value):
    from storage.database import SessionLocal
    from storage.models import SettingsModel
    session = SessionLocal()
    try:
        row = session.query(SettingsModel).filter_by(key=key).first()
        if row:
            row.value = value
        else:
            session.add(SettingsModel(key=key, value=value))
        session.commit()
    finally:
        session.close()


def get_model_for_task(task):
    if task == "triage":
        return _read_setting("triage_model") or DEFAULT_TRIAGE
    return _read_setting("deep_model") or DEFAULT_DEEP


def set_model_for_task(task, model_name):
    key = "triage_model" if task == "triage" else "deep_model"
    _write_setting(key, model_name)


def list_ollama_models(endpoint_root="http://localhost:11434"):
    import requests
    try:
        r = requests.get(f"{endpoint_root}/api/tags", timeout=5)
        if r.status_code != 200:
            return []
        data = r.json()
        return [m.get("name") for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []
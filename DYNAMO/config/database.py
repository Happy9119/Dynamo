import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+psycopg://localhost/dynamo_recon",
)
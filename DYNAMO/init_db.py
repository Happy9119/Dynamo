from storage.database import engine
from storage.models import Base

Base.metadata.create_all(bind=engine)
print("[+] Database initialized")
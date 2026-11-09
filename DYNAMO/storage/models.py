from datetime import datetime
from core.datetime_utils import now as _now

def _localnow():
    return _now()

_utcnow = _localnow


from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, ForeignKey, Float,
)
from sqlalchemy.orm import relationship
from storage.database import Base


# ────────────────────────────────────────────────────────────────────────────
# DOMAIN (new)
# ────────────────────────────────────────────────────────────────────────────

class DomainModel(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    apex = Column(String, unique=True, index=True, nullable=False)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    is_active = Column(Boolean, default=True)

    assets = relationship(
        "AssetModel",
        secondary="domain_assets",
        back_populates="domains",
        overlaps="domain_links,domain,asset",
    )


class DomainAssetModel(Base):
    __tablename__ = "domain_assets"

    domain_id = Column(Integer, ForeignKey("domains.id"), primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), primary_key=True)

    discovered_via = Column(String)          # "subfinder" | "crt" | "manual" | "scan_target"
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)


# ────────────────────────────────────────────────────────────────────────────
# SCANS
# ────────────────────────────────────────────────────────────────────────────

class ScanAssetModel(Base):
    __tablename__ = "scan_assets"
    scan_id = Column(Integer, ForeignKey("scans.id"), primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), primary_key=True)
    observed_at = Column(DateTime, default=_utcnow)


class ScanModel(Base):
    __tablename__ = "scans"
    id           = Column(Integer, primary_key=True)
    target       = Column(String, index=True)
    started_at   = Column(DateTime, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)
    status       = Column(String, default="running")
    mode         = Column(String, default="quick")

    subfinder_count        = Column(Integer, default=0)
    crt_count              = Column(Integer, default=0)
    gau_count              = Column(Integer, default=0)
    wayback_count          = Column(Integer, default=0)
    httpx_count            = Column(Integer, default=0)
    nmap_ip_count          = Column(Integer, default=0)
    nmap_service_count     = Column(Integer, default=0)
    katana_count           = Column(Integer, default=0)
    ffuf_count             = Column(Integer, default=0)
    nuclei_count           = Column(Integer, default=0)
    sqli_count             = Column(Integer, default=0)
    vapt_count             = Column(Integer, default=0)
    correlated_asset_count = Column(Integer, default=0)
    saved_asset_count      = Column(Integer, default=0)
    error_message          = Column(Text, nullable=True)
    tool_status_json       = Column(Text, nullable=True)


    scans_assets = relationship("ScanAssetModel", backref="scan",
                                cascade="all, delete-orphan")
    assets = relationship(
        "AssetModel", secondary="scan_assets",
        back_populates="scans", overlaps="scans_assets,scan",
    )

    observations = relationship(
        "AssetObservationModel",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

# ────────────────────────────────────────────────────────────────────────────
# ASSETS
# ────────────────────────────────────────────────────────────────────────────

class AssetModel(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    url = Column(String, nullable=True)
    asset_value = Column(String, index=True)
    ip_address = Column(String, index=True, nullable=True)
    title = Column(String)
    status_code = Column(Integer, nullable=True)

    # new — fast path to the current apex domain
    domain_id = Column(Integer, ForeignKey("domains.id"), index=True, nullable=True)

    technologies = Column(String)

    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    is_active = Column(Boolean, default=True)

    risk_score = Column(Integer, default=0)
    risk_summary = Column(String)

    ai_analysis_json = Column(Text, nullable=True)
    ai_last_updated = Column(DateTime, nullable=True)

    scans = relationship(
        "ScanModel",
        secondary="scan_assets",
        back_populates="assets",
        overlaps="scans_assets,scan",
    )

    # new — many-to-many via domain_assets
    domains = relationship(
        "DomainModel",
        secondary="domain_assets",
        back_populates="assets",
        overlaps="domain_links,domain,asset",
    )

    ip_addresses = relationship("AssetIPModel", back_populates="asset",
                                cascade="all, delete-orphan")
    services = relationship("ServiceModel", back_populates="asset",
                            cascade="all, delete-orphan")
    change_events = relationship("ChangeEventModel", back_populates="asset",
                                 cascade="all, delete-orphan")
    cves = relationship("AssetCVEModel", back_populates="asset",
                        cascade="all, delete-orphan")

    urls            = relationship("AssetURLModel", back_populates="asset",
                                   cascade="all, delete-orphan")
    nuclei_findings = relationship("NucleiFindingModel", back_populates="asset",
                                   cascade="all, delete-orphan")
    sqli_findings   = relationship("SQLiFindingModel", back_populates="asset",
                                   cascade="all, delete-orphan")
    vulns = relationship("AssetVulnModel", back_populates="asset",
                        cascade="all, delete-orphan")
    observations = relationship("AssetObservationModel",
                                back_populates="asset",
                                cascade="all, delete-orphan")


class AssetObservationModel(Base):
    __tablename__ = "asset_observations"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    observed_at = Column(DateTime, default=_utcnow)
    ip_address = Column(String)
    technologies = Column(Text)
    services_json = Column(Text)
    cves_json = Column(Text)
    vapt_json = Column(Text)        # NEW
    nuclei_json = Column(Text)      # NEW
    sqli_json = Column(Text)        # NEW
    risk_score = Column(Integer)
    risk_summary = Column(Text)
    ai_analysis_json = Column(Text)
    
    asset = relationship("AssetModel", back_populates="observations")
    scan = relationship("ScanModel", back_populates="observations")

class AssetIPModel(Base):
    __tablename__ = "asset_ips"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    ip_address = Column(String, nullable=False, index=True)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    is_active = Column(Boolean, default=True)
    asset = relationship("AssetModel", back_populates="ip_addresses")


class ServiceModel(Base):
    __tablename__ = "services"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    port = Column(Integer)
    protocol = Column(String)
    service_name = Column(String)
    product = Column(String)
    version = Column(String)
    asset = relationship("AssetModel", back_populates="services")


class AssetCVEModel(Base):
    __tablename__ = "asset_cves"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    cve_id = Column(String)
    severity = Column(String)
    cvss = Column(Float)
    description = Column(Text)
    match_confidence = Column(String, nullable=True)  # <-- ADD THIS
    created_at = Column(DateTime, default=_utcnow)
    asset = relationship("AssetModel", back_populates="cves")


class ChangeEventModel(Base):
    __tablename__ = "change_events"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    event_type = Column(String)
    old_value = Column(String)
    new_value = Column(String)
    created_at = Column(DateTime, default=_utcnow)
    asset = relationship("AssetModel", back_populates="change_events")


class AssetURLModel(Base):
    __tablename__ = "asset_urls"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    url = Column(Text)
    source = Column(String)
    has_params = Column(Boolean, default=False)
    last_scan_id = Column(Integer, nullable=True)
    asset = relationship("AssetModel", back_populates="urls")


class NucleiFindingModel(Base):
    __tablename__ = "nuclei_findings"
    id = Column(Integer, primary_key=True)
    host = Column(String)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    template_id = Column(String)
    name = Column(String)
    severity = Column(String)
    matched_at = Column(Text)
    description = Column(Text)
    raw_json = Column(Text)
    created_at = Column(DateTime, default=_utcnow)
    asset = relationship("AssetModel", back_populates="nuclei_findings")


class SQLiFindingModel(Base):
    __tablename__ = "sqli_findings"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    url = Column(Text)
    technique = Column(String)
    payload = Column(Text)
    created_at = Column(DateTime, default=_utcnow)
    asset = relationship("AssetModel", back_populates="sqli_findings")


class AssetVulnModel(Base):
    __tablename__ = "asset_vulns"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), index=True)
    vuln_type = Column(String, index=True)
    severity = Column(String, index=True)
    url = Column(Text)
    parameter = Column(String)
    evidence = Column(Text)
    remediation = Column(Text)
    detected_at = Column(DateTime, default=_utcnow)
    asset = relationship("AssetModel", back_populates="vulns")


class ScanProgressModel(Base):
    __tablename__ = "scan_progress"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    phase = Column(String)
    status = Column(String) # "running", "completed", "failed"
    count = Column(Integer, default=0)
    last_updated = Column(DateTime, default=_utcnow, onupdate=_utcnow)

class PhaseResultModel(Base):
    __tablename__ = "phase_results"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), index=True)
    phase_name = Column(String, index=True)
    result_json = Column(Text) # Stores intermediate lists (subdomains, ips, etc)


class AICacheModel(Base):
    __tablename__ = "ai_cache"
    id = Column(Integer, primary_key=True)
    asset_hash = Column(String, unique=True, index=True)
    task = Column(String)
    response_json = Column(Text)
    created_at = Column(DateTime, default=_utcnow)


class SettingsModel(Base):
    __tablename__ = "settings"
    key = Column(String, primary_key=True)
    value = Column(Text)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
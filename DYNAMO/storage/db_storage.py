import json
from urllib.parse import urlparse
from datetime import datetime
from core.datetime_utils import now as _now
from storage.models import _utcnow

from storage.database import SessionLocal
from storage.models import (
    ScanModel, ScanAssetModel, AssetModel, AssetCVEModel, ServiceModel,
    ChangeEventModel, AssetObservationModel,
    AssetURLModel, NucleiFindingModel, SQLiFindingModel,
    DomainModel, DomainAssetModel, AssetIPModel, AssetVulnModel,
)
from core.risk_engine import calculate_risk
from core.domain_utils import extract_apex, host_belongs_to_apex
from config.tools import AI_RISK_THRESHOLD as _DEFAULT_AI_RISK

from schemas.asset import Asset, Service, NucleiFinding, SQLiFinding, VulnFinding


CLEAN_STATUSES = {"OK", "EMPTY"}


def _is_clean(tool_status, key):
    return tool_status.get(key) in CLEAN_STATUSES


def _is_ip(value):
    if not value:
        return False
    import ipaddress
    try:
        ipaddress.ip_address(str(value))
        return True
    except (ValueError, TypeError):
        return False


def _pick_primary_ip(resolved_ips, previous_ip):
    if not resolved_ips:
        return None
    pool = set(resolved_ips)
    if previous_ip and previous_ip in pool:
        return previous_ip
    ipv4 = sorted(ip for ip in pool if ":" not in ip)
    if ipv4:
        return ipv4[0]
    return sorted(pool)[0]


def create_scan(target, mode: str = "quick"):
    session = SessionLocal()
    try:
        scan = ScanModel(target=target, mode=mode)
        session.add(scan)
        session.commit()
        session.refresh(scan)
        print(f"[+] Created scan {scan.id} ({target}, mode={mode})")
        return scan.id
    finally:
        session.close()


def update_scan_status(scan_id, status, completed_at=None,
                       error_message=None, **metrics):
    session = SessionLocal()
    try:
        scan = session.query(ScanModel).get(scan_id)
        if not scan:
            print(f"[!] Scan {scan_id} was deleted from DB. Ignoring status update.")
            return
        scan.status = status
        if completed_at:
            scan.completed_at = completed_at
        if error_message:
            scan.error_message = error_message
        for key, value in metrics.items():
            if hasattr(scan, key):
                setattr(scan, key, value)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def log_change_event(session, asset_id, event_type, old_value, new_value):
    session.add(ChangeEventModel(
        asset_id=asset_id, event_type=event_type,
        old_value=old_value, new_value=new_value,
    ))


def upsert_domain(session, apex: str, touch: bool = True) -> int:
    row = session.query(DomainModel).filter_by(apex=apex).first()
    if row is None:
        row = DomainModel(apex=apex)
        session.add(row)
        session.flush()
    if touch:
        row.last_seen = _now()
        row.is_active = True
    return row.id


def link_domain_asset(session, domain_id: int, asset_id: int,
                      discovered_via: str = "scan") -> None:
    link = (
        session.query(DomainAssetModel)
        .filter_by(domain_id=domain_id, asset_id=asset_id)
        .first()
    )
    now = _now()
    if link is None:
        session.add(DomainAssetModel(
            domain_id=domain_id, asset_id=asset_id,
            discovered_via=discovered_via,
            first_seen=now, last_seen=now,
        ))
    else:
        link.last_seen = now


def deactivate_missing_assets(current_assets, domain, scanned_hosts=None):
    session = SessionLocal()
    try:
        apex = extract_apex(domain)
        if not apex:
            return

        dom = session.query(DomainModel).filter_by(apex=apex).first()
        if not dom:
            return

        scanned_hosts = scanned_hosts or []

        db_assets = (
            session.query(AssetModel)
            .filter(AssetModel.is_active == True)
            .filter(AssetModel.domain_id == dom.id)
            .all()
        )

        touched = 0
        for asset in db_assets:
            is_ip_asset = _is_ip(asset.asset_value)

            if not is_ip_asset and scanned_hosts and not any(
                host_belongs_to_apex(asset.asset_value, h) for h in scanned_hosts
            ):
                continue

            if asset.asset_value not in current_assets:
                asset.is_active = False
                asset.last_seen = _now()
                log_change_event(session, asset.id, "asset_deactivated", "", "")
                print(f"[+] Marked inactive: {asset.asset_value}")
                touched += 1

        if touched:
            session.commit()
        else:
            session.rollback()
    except Exception as e:
        session.rollback()
        print(f"[!] Failed to deactivate missing assets: {e}")
        raise
    finally:
        session.close()


def get_active_asset_count(domain: str) -> int:
    session = SessionLocal()
    try:
        apex = extract_apex(domain)
        if not apex:
            return 0
        dom = session.query(DomainModel).filter_by(apex=apex).first()
        if not dom:
            return 0
        return (
            session.query(AssetModel)
            .filter(AssetModel.domain_id == dom.id)
            .filter(AssetModel.is_active == True)
            .count()
        )
    finally:
        session.close()


def _sync_asset_ips(session, asset_id, resolved_ips):
    now = _now()
    existing = {
        row.ip_address: row
        for row in session.query(AssetIPModel).filter_by(asset_id=asset_id).all()
    }
    incoming = {ip for ip in (resolved_ips or []) if ip}

    for ip in incoming:
        if ip in existing:
            row = existing[ip]
            row.last_seen = now
            row.is_active = True
        else:
            session.add(AssetIPModel(
                asset_id=asset_id, ip_address=ip,
                first_seen=now, last_seen=now, is_active=True,
            ))
            log_change_event(session, asset_id, "ip_added", "", ip)

    for ip, row in existing.items():
        if ip not in incoming and row.is_active:
            row.is_active = False
            row.last_seen = now
            log_change_event(session, asset_id, "ip_removed", ip, "")


def _sync_services(session, asset_id, new_services):
    existing = {
        (s.port, s.protocol): s
        for s in session.query(ServiceModel).filter_by(asset_id=asset_id).all()
    }
    incoming = {}
    for svc in new_services:
        incoming[(svc.port, svc.protocol)] = svc

    for key, svc in incoming.items():
        if key in existing:
            row = existing[key]
            old_fp = (row.service_name or "?", row.product or "", row.version or "")
            new_fp = (svc.service_name or "?", svc.product or "", svc.version or "")
            if old_fp != new_fp:
                log_change_event(
                    session, asset_id, "service_fingerprint_changed",
                    f"{svc.port}/{svc.protocol}: {'|'.join(old_fp)}",
                    f"{svc.port}/{svc.protocol}: {'|'.join(new_fp)}",
                )
            row.service_name = (
                svc.service_name
                if svc.service_name and svc.service_name not in ("unknown", "", None)
                else row.service_name
            )
            row.product = svc.product or row.product
            row.version = svc.version or row.version
        else:
            session.add(ServiceModel(
                asset_id=asset_id,
                port=svc.port, protocol=svc.protocol,
                service_name=svc.service_name,
                product=svc.product, version=svc.version,
            ))
            log_change_event(
                session, asset_id, "service_added", "",
                f"{svc.port}/{svc.protocol} ({svc.service_name or '?'})",
            )

    for key, row in existing.items():
        if key not in incoming:
            log_change_event(
                session, asset_id, "service_removed",
                f"{row.port}/{row.protocol} ({row.service_name or '?'})", "",
            )
            session.delete(row)


def _sync_technologies(session, asset_id, old_string, new_string):
    old_set = {t.strip() for t in (old_string or "").split(",") if t.strip()}
    new_set = {t.strip() for t in (new_string or "").split(",") if t.strip()}
    for t in sorted(new_set - old_set):
        log_change_event(session, asset_id, "technology_added", "", t)
    for t in sorted(old_set - new_set):
        log_change_event(session, asset_id, "technology_removed", t, "")


def _sync_cves(session, asset_id, incoming_cves, mode):
    existing = {
        row.cve_id: row
        for row in session.query(AssetCVEModel).filter_by(asset_id=asset_id).all()
    }

    if mode == "full":
        for cve_id, row in existing.items():
            session.delete(row)
        for cve in incoming_cves:
            cve_id = (cve.get("cve") or "").strip() if isinstance(cve, dict) else ""
            if not cve_id:
                continue
            session.add(AssetCVEModel(
                asset_id=asset_id, cve_id=cve_id,
                severity=cve.get("severity"),
                cvss=cve.get("cvss"),
                description=cve.get("description"),
                match_confidence=cve.get("match_confidence"),
            ))
        return

    seen = set()
    for cve in incoming_cves:
        cve_id = (cve.get("cve") or "").strip() if isinstance(cve, dict) else ""
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        row = existing.get(cve_id)
        if row is not None:
            if cve.get("severity"):
                row.severity = cve.get("severity")
            if cve.get("cvss") is not None:
                row.cvss = cve.get("cvss")
            if cve.get("description"):
                row.description = cve.get("description")
            if cve.get("match_confidence"):
                row.match_confidence = cve.get("match_confidence")
        else:
            session.add(AssetCVEModel(
                asset_id=asset_id, cve_id=cve_id,
                severity=cve.get("severity"),
                cvss=cve.get("cvss"),
                description=cve.get("description"),
                match_confidence=cve.get("match_confidence"),
            ))


def _sync_nuclei(session, asset_id, incoming, clean):
    if clean:
        session.query(NucleiFindingModel).filter_by(asset_id=asset_id).delete()
        for f in incoming or []:
            session.add(NucleiFindingModel(
                asset_id=asset_id, host=f.host,
                template_id=f.template_id, name=f.name,
                severity=f.severity, matched_at=f.matched_at,
                description=f.description,
                raw_json=json.dumps(f.raw),
                created_at=_now(),
            ))
        return

    existing = {
        (n.template_id or "", n.matched_at or ""): n
        for n in session.query(NucleiFindingModel).filter_by(asset_id=asset_id).all()
    }
    seen = set()
    for f in incoming or []:
        key = (f.template_id or "", f.matched_at or "")
        if key in seen:
            continue
        seen.add(key)
        row = existing.get(key)
        if row:
            if f.name:
                row.name = f.name
            if f.severity:
                row.severity = f.severity
            if f.description:
                row.description = f.description
        else:
            session.add(NucleiFindingModel(
                asset_id=asset_id, host=f.host,
                template_id=f.template_id, name=f.name,
                severity=f.severity, matched_at=f.matched_at,
                description=f.description,
                raw_json=json.dumps(f.raw),
                created_at=_now(),
            ))


def _sync_vapt(session, asset_id, incoming, clean):
    if clean:
        session.query(AssetVulnModel).filter_by(asset_id=asset_id).delete()
        for v in incoming or []:
            session.add(AssetVulnModel(
                asset_id=asset_id,
                vuln_type=v.vuln_type, severity=v.severity,
                url=v.url, parameter=v.parameter,
                evidence=v.evidence, remediation=v.remediation,
            ))
        return

    existing = {
        (v.vuln_type, v.url, v.parameter or ""): v
        for v in session.query(AssetVulnModel).filter_by(asset_id=asset_id).all()
    }
    seen = set()
    for v in incoming or []:
        key = (v.vuln_type, v.url, v.parameter or "")
        if key in seen:
            continue
        seen.add(key)
        row = existing.get(key)
        if row:
            if v.severity:
                row.severity = v.severity
            if v.evidence:
                row.evidence = v.evidence
            if v.remediation:
                row.remediation = v.remediation
        else:
            session.add(AssetVulnModel(
                asset_id=asset_id,
                vuln_type=v.vuln_type, severity=v.severity,
                url=v.url, parameter=v.parameter,
                evidence=v.evidence, remediation=v.remediation,
            ))


def _sync_sqli(session, asset_id, incoming, clean):
    if clean:
        session.query(SQLiFindingModel).filter_by(asset_id=asset_id).delete()
        for s in incoming or []:
            if s.vulnerable:
                session.add(SQLiFindingModel(
                    asset_id=asset_id, url=s.url,
                    technique=s.technique, payload=s.payload,
                    created_at=_now(),
                ))
        return

    existing = {
        s.url: s
        for s in session.query(SQLiFindingModel).filter_by(asset_id=asset_id).all()
    }
    seen = set()
    for s in incoming or []:
        if not s.vulnerable or not s.url or s.url in seen:
            continue
        seen.add(s.url)
        row = existing.get(s.url)
        if row:
            if s.technique:
                row.technique = s.technique
            if s.payload:
                row.payload = s.payload
        else:
            session.add(SQLiFindingModel(
                asset_id=asset_id, url=s.url,
                technique=s.technique, payload=s.payload,
                created_at=_now(),
            ))


def save_asset_to_db(asset, scan_id, mode="full", tool_status=None):
    if not asset or not asset.asset_value or not asset.asset_value.strip():
        print("[!] Skipping save_asset_to_db: empty asset_value")
        return None

    tool_status = tool_status or {}
    nuclei_clean = _is_clean(tool_status, "nuclei")
    vapt_clean = _is_clean(tool_status, "vapt")
    sqlmap_clean = _is_clean(tool_status, "sqlmap")

    session = SessionLocal()
    try:
        scan_row = session.query(ScanModel).get(scan_id)
        apex = extract_apex(scan_row.target) if scan_row else None
        domain_id = upsert_domain(session, apex) if apex else None

        existing_asset = (
            session.query(AssetModel)
            .filter_by(asset_value=asset.asset_value, domain_id=domain_id)
            .first()
        )

        if existing_asset is None and domain_id is not None:
            orphan = (
                session.query(AssetModel)
                .filter_by(asset_value=asset.asset_value)
                .filter(AssetModel.domain_id.is_(None))
                .first()
            )
            if orphan is not None:
                orphan.domain_id = domain_id
                existing_asset = orphan
                print(f"[+] Adopted orphan asset: {asset.asset_value} → domain_id={domain_id}")

        risk_score, risk_summary = calculate_risk(asset)
        previous_ip = existing_asset.ip_address if existing_asset else None
        new_ip = _pick_primary_ip(asset.resolved_ips or [], previous_ip)
        new_tech = ",".join([str(t) for t in asset.technologies if t])
        new_cve_ids = {c["cve"] for c in asset.cves if isinstance(c, dict) and c.get("cve")}
        ai_json_str = asset.ai_analysis.model_dump_json() if asset.ai_analysis else None

        if existing_asset:
            old_ip = existing_asset.ip_address
            incoming_ips = set(asset.resolved_ips or [])
            if new_ip and old_ip and old_ip != new_ip and old_ip not in incoming_ips:
                log_change_event(session, existing_asset.id, "ip_changed", old_ip, new_ip)

            old_tech = existing_asset.technologies or ""
            if old_tech != new_tech:
                _sync_technologies(session, existing_asset.id, old_tech, new_tech)

            old_cve_ids = {cve.cve_id for cve in existing_asset.cves}
            for added_cve in sorted(new_cve_ids - old_cve_ids):
                log_change_event(session, existing_asset.id, "cve_added", "", added_cve)
            for resolved_cve in sorted(old_cve_ids - new_cve_ids):
                if mode == "full":
                    log_change_event(session, existing_asset.id, "cve_resolved", resolved_cve, "")

            if new_ip:
                existing_asset.ip_address = new_ip
            if asset.url:
                existing_asset.url = asset.url
            existing_asset.title = asset.title
            existing_asset.status_code = asset.status_code
            existing_asset.technologies = new_tech
            existing_asset.last_seen = _now()
            existing_asset.is_active = True
            existing_asset.risk_score = risk_score
            existing_asset.risk_summary = risk_summary

            if ai_json_str:
                existing_asset.ai_analysis_json = ai_json_str
                existing_asset.ai_last_updated = _now()

            session.flush()
            asset_id = existing_asset.id
            asset_row = existing_asset
            print(f"[+] Updated existing asset: {asset.asset_value}")
        else:
            asset_row = AssetModel(
                asset_value=asset.asset_value,
                ip_address=new_ip,
                url=asset.url, title=asset.title,
                status_code=asset.status_code,
                domain_id=domain_id,
                technologies=new_tech,
                first_seen=_now(), last_seen=_now(),
                is_active=True,
                risk_score=risk_score, risk_summary=risk_summary,
                ai_analysis_json=ai_json_str,
                ai_last_updated=_now() if ai_json_str else None,
            )
            session.add(asset_row)
            session.flush()
            asset_id = asset_row.id
            log_change_event(session, asset_id, "new_asset", "", asset.asset_value)
            for cve_id in sorted(new_cve_ids):
                log_change_event(session, asset_id, "cve_added", "", cve_id)
            print(f"[+] Created new asset: {asset.asset_value}")

        if domain_id:
            host_candidates = set()
            if asset.asset_value:
                host_candidates.add(asset.asset_value.lower())
            if asset.url:
                parsed = urlparse(asset.url)
                if parsed.hostname:
                    host_candidates.add(parsed.hostname.lower())
            for ip in (asset.resolved_ips or []):
                host_candidates.add(ip.lower())

            belongs = any(host_belongs_to_apex(h, apex) for h in host_candidates)
            if belongs:
                asset_row.domain_id = domain_id
                link_domain_asset(session, domain_id, asset_id, discovered_via="scan")
            else:
                if asset_row.domain_id is None:
                    asset_row.domain_id = domain_id
                    link_domain_asset(session, domain_id, asset_id,
                                      discovered_via="scan-out-of-scope-host")

        already_linked = (
            session.query(ScanAssetModel)
            .filter_by(scan_id=scan_id, asset_id=asset_id)
            .first()
        )
        if not already_linked:
            session.add(ScanAssetModel(scan_id=scan_id, asset_id=asset_id))

        _sync_asset_ips(session, asset_id, asset.resolved_ips or [])
        _sync_services(session, asset_id, asset.services)
        _sync_cves(session, asset_id, asset.cves, mode)

        if mode == "full":
            session.query(AssetURLModel).filter_by(asset_id=asset_id).delete()
        else:
            session.query(AssetURLModel).filter_by(asset_id=asset_id).filter(
                AssetURLModel.source.in_(["gau/wayback", "live_archive"])
            ).delete(synchronize_session=False)

        for url in asset.historical_urls or []:
            session.add(AssetURLModel(asset_id=asset_id, url=url,
                                      source="gau/wayback",
                                      has_params=("?" in url and "=" in url),
                                      last_scan_id=scan_id))
        for url in asset.live_urls or []:
            session.add(AssetURLModel(asset_id=asset_id, url=url,
                                      source="live_archive",
                                      has_params=("?" in url and "=" in url),
                                      last_scan_id=scan_id))

        if mode == "full":
            for url in asset.crawled_urls or []:
                session.add(AssetURLModel(asset_id=asset_id, url=url,
                                          source="katana",
                                          has_params=("?" in url and "=" in url),
                                          last_scan_id=scan_id))
            for url in asset.discovered_paths or []:
                session.add(AssetURLModel(asset_id=asset_id, url=url,
                                          source="ffuf", last_scan_id=scan_id))
            for url in asset.js_endpoints or []:
                session.add(AssetURLModel(asset_id=asset_id, url=url,
                                          source="js", last_scan_id=scan_id))

        if mode == "full":
            _sync_nuclei(session, asset_id, asset.nuclei_findings, nuclei_clean)
            _sync_sqli(session, asset_id, asset.sqli_findings, sqlmap_clean)
            _sync_vapt(session, asset_id, asset.vulns, vapt_clean)

        vapt_json_val = (
            json.dumps([v.model_dump() for v in asset.vulns])
            if mode == "full" and vapt_clean else None
        )
        nuclei_json_val = (
            json.dumps([n.model_dump() for n in asset.nuclei_findings])
            if mode == "full" and nuclei_clean else None
        )
        sqli_json_val = (
            json.dumps([s.model_dump() for s in asset.sqli_findings])
            if mode == "full" and sqlmap_clean else None
        )

        session.add(AssetObservationModel(
            scan_id=scan_id, asset_id=asset_id,
            observed_at=_now(),
            ip_address=new_ip, technologies=new_tech,
            services_json=json.dumps([
                {"port": s.port, "protocol": s.protocol,
                 "service_name": s.service_name,
                 "product": s.product, "version": s.version}
                for s in asset.services
            ]),
            cves_json=json.dumps(asset.cves),
            vapt_json=vapt_json_val,
            nuclei_json=nuclei_json_val,
            sqli_json=sqli_json_val,
            risk_score=risk_score, risk_summary=risk_summary,
            ai_analysis_json=ai_json_str,
        ))

        session.commit()
        return asset_id

    except Exception as e:
        session.rollback()
        print(f"[!] Failed to save asset {asset.asset_value}: {e}")
        raise
    finally:
        session.close()


def load_asset_for_ai(asset_id: int) -> Asset | None:
    session = SessionLocal()
    try:
        row = session.query(AssetModel).get(asset_id)
        if not row:
            return None

        ips = [
            ip.ip_address for ip in
            session.query(AssetIPModel)
            .filter(AssetIPModel.asset_id == asset_id)
            .filter(AssetIPModel.is_active == True)
            .all()
        ]
        if not ips and row.ip_address:
            ips = [row.ip_address]

        services = [
            Service(port=s.port, protocol=s.protocol,
                    service_name=s.service_name,
                    product=s.product, version=s.version)
            for s in session.query(ServiceModel).filter_by(asset_id=asset_id).all()
        ]

        cves = [
            {"cve": c.cve_id, "severity": c.severity, "cvss": c.cvss,
             "description": c.description, "match_confidence": c.match_confidence}
            for c in session.query(AssetCVEModel).filter_by(asset_id=asset_id).all()
        ]

        nuc = [
            NucleiFinding(template_id=f.template_id, name=f.name,
                          severity=f.severity, matched_at=f.matched_at,
                          host=f.host, description=f.description)
            for f in session.query(NucleiFindingModel).filter_by(asset_id=asset_id).all()
        ]

        sqli = [
            SQLiFinding(url=s.url, vulnerable=True,
                        technique=s.technique, payload=s.payload)
            for s in session.query(SQLiFindingModel).filter_by(asset_id=asset_id).all()
        ]

        vulns = [
            VulnFinding(vuln_type=v.vuln_type, severity=v.severity, url=v.url,
                        parameter=v.parameter, evidence=v.evidence,
                        remediation=v.remediation)
            for v in session.query(AssetVulnModel).filter_by(asset_id=asset_id).all()
        ]

        url_rows = session.query(AssetURLModel).filter_by(asset_id=asset_id).all()
        historical = [u.url for u in url_rows if u.source == "gau/wayback"]
        live = [u.url for u in url_rows if u.source == "live_archive"]
        crawled = [u.url for u in url_rows if u.source == "katana"]
        discovered = [u.url for u in url_rows if u.source == "ffuf"]
        js_endpoints = [u.url for u in url_rows if u.source == "js"]
        params = [u.url for u in url_rows if u.has_params]

        techs = [t.strip() for t in (row.technologies or "").split(",") if t.strip()]

        return Asset(
            asset_value=row.asset_value,
            resolved_ips=ips,
            url=row.url, title=row.title, status_code=row.status_code,
            technologies=techs, services=services,
            historical_urls=historical, live_urls=live,
            crawled_urls=crawled, parameter_urls=params,
            discovered_paths=discovered, js_endpoints=js_endpoints,
            nuclei_findings=nuc, sqli_findings=sqli, vulns=vulns,
            risk_score=row.risk_score, risk_summary=row.risk_summary,
            cves=cves,
        )
    finally:
        session.close()


def list_pending_ai(scan_id: int | None = None,
                    domain_id: int | None = None,
                    risk_min: int | None = None) -> list[int]:
    if risk_min is None:
        risk_min = _DEFAULT_AI_RISK

    session = SessionLocal()
    try:
        from sqlalchemy import or_
        q = session.query(AssetModel.id).filter(
            AssetModel.risk_score >= risk_min,
            AssetModel.is_active == True,
            or_(
                AssetModel.ai_analysis_json.is_(None),
                AssetModel.ai_last_updated < AssetModel.last_seen
            )
        )
        if scan_id is not None:
            q = q.filter(AssetModel.scans.any(ScanModel.id == scan_id))
        if domain_id is not None:
            q = q.filter(AssetModel.domain_id == domain_id)
        return [row[0] for row in q.all()]
    finally:
        session.close()


def save_ai_analysis(asset_id: int, ai_json: str, scan_id: int | None = None) -> None:
    session = SessionLocal()
    try:
        row = session.query(AssetModel).get(asset_id)
        if not row:
            return
        row.ai_analysis_json = ai_json
        row.ai_last_updated = _now()

        q = session.query(AssetObservationModel).filter_by(asset_id=asset_id)
        if scan_id is not None:
            q = q.filter_by(scan_id=scan_id)
        latest_obs = q.order_by(AssetObservationModel.observed_at.desc()).first()
        if latest_obs is not None:
            latest_obs.ai_analysis_json = ai_json

        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reconcile_stale_scans(max_age_hours: int = 6) -> int:
    from datetime import timedelta
    threshold = _utcnow() - timedelta(hours=max_age_hours)
    session = SessionLocal()
    try:
        stale = (
            session.query(ScanModel)
            .filter(ScanModel.status == "running")
            .filter(ScanModel.started_at < threshold)
            .all()
        )
        for scan in stale:
            scan.status = "abandoned"
            scan.error_message = (
                f"Pipeline did not complete within {max_age_hours}h; "
                f"process likely crashed or was killed"
            )
            scan.completed_at = _utcnow()

        if stale:
            session.commit()
            print(f"[+] Reconciled {len(stale)} stale 'running' scan(s) to 'abandoned'")
        return len(stale)
    except Exception as e:
        session.rollback()
        print(f"[!] reconcile_stale_scans failed: {e}")
        return 0
    finally:
        session.close()


def load_assets_for_ai_batch(asset_ids: list[int]) -> list[Asset]:
    if not asset_ids:
        return []
    session = SessionLocal()
    try:
        rows = session.query(AssetModel).filter(AssetModel.id.in_(asset_ids)).all()

        ips = session.query(AssetIPModel).filter(AssetIPModel.asset_id.in_(asset_ids)).all()
        services = session.query(ServiceModel).filter(ServiceModel.asset_id.in_(asset_ids)).all()
        cves = session.query(AssetCVEModel).filter(AssetCVEModel.asset_id.in_(asset_ids)).all()
        nuc = session.query(NucleiFindingModel).filter(NucleiFindingModel.asset_id.in_(asset_ids)).all()
        sqli = session.query(SQLiFindingModel).filter(SQLiFindingModel.asset_id.in_(asset_ids)).all()
        vulns = session.query(AssetVulnModel).filter(AssetVulnModel.asset_id.in_(asset_ids)).all()
        urls = session.query(AssetURLModel).filter(AssetURLModel.asset_id.in_(asset_ids)).all()

        from collections import defaultdict
        ips_map, svcs_map, cves_map, nuc_map, sqli_map, vulns_map, urls_map = (
            defaultdict(list), defaultdict(list), defaultdict(list),
            defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
        )

        for i in ips: ips_map[i.asset_id].append(i)
        for s in services: svcs_map[s.asset_id].append(s)
        for c in cves: cves_map[c.asset_id].append(c)
        for n in nuc: nuc_map[n.asset_id].append(n)
        for s in sqli: sqli_map[s.asset_id].append(s)
        for v in vulns: vulns_map[v.asset_id].append(v)
        for u in urls: urls_map[u.asset_id].append(u)

        results = []
        for row in rows:
            aid = row.id
            techs = [t.strip() for t in (row.technologies or "").split(",") if t.strip()]
            results.append(Asset(
                asset_value=row.asset_value,
                resolved_ips=[ip.ip_address for ip in ips_map[aid] if ip.is_active],
                url=row.url, title=row.title, status_code=row.status_code,
                technologies=techs,
                services=[Service(port=s.port, protocol=s.protocol,
                                  service_name=s.service_name,
                                  product=s.product, version=s.version)
                          for s in svcs_map[aid]],
                historical_urls=[u.url for u in urls_map[aid] if u.source == "gau/wayback"],
                live_urls=[u.url for u in urls_map[aid] if u.source == "live_archive"],
                crawled_urls=[u.url for u in urls_map[aid] if u.source == "katana"],
                parameter_urls=[u.url for u in urls_map[aid] if u.has_params],
                discovered_paths=[u.url for u in urls_map[aid] if u.source == "ffuf"],
                js_endpoints=[u.url for u in urls_map[aid] if u.source == "js"],
                nuclei_findings=[NucleiFinding(template_id=f.template_id, name=f.name,
                                               severity=f.severity, matched_at=f.matched_at,
                                               host=f.host) for f in nuc_map[aid]],
                sqli_findings=[SQLiFinding(url=s.url, vulnerable=True,
                                           technique=s.technique) for s in sqli_map[aid]],
                vulns=[VulnFinding(vuln_type=v.vuln_type, severity=v.severity,
                                   url=v.url, evidence=v.evidence)
                       for v in vulns_map[aid]],
                risk_score=row.risk_score, risk_summary=row.risk_summary,
                cves=[{"cve": c.cve_id, "severity": c.severity,
                       "cvss": c.cvss, "match_confidence": c.match_confidence}
                      for c in cves_map[aid]],
            ))
        return results
    finally:
        session.close()


def prune_ai_cache(max_age_days: int = 30) -> int:
    from datetime import timedelta
    cutoff = _now() - timedelta(days=max_age_days)
    session = SessionLocal()
    try:
        from storage.models import AICacheModel
        deleted = session.query(AICacheModel).filter(
            AICacheModel.created_at < cutoff
        ).delete(synchronize_session=False)
        session.commit()
        return int(deleted)
    except Exception:
        session.rollback()
        return 0
    finally:
        session.close()
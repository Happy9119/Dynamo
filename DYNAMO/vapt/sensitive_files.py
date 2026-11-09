import asyncio
from urllib.parse import urljoin


PATHS = [
    ("/.git/config", "high", "git_config_exposed"),
    ("/.git/HEAD", "high", "git_head_exposed"),
    ("/.svn/entries", "medium", "svn_entries_exposed"),
    ("/.svn/wc.db", "medium", "svn_wc_exposed"),
    ("/.env", "critical", "env_file_exposed"),
    ("/.env.local", "critical", "env_local_exposed"),
    ("/.env.production", "critical", "env_production_exposed"),
    ("/.env.backup", "critical", "env_backup_exposed"),
    ("/config.php.bak", "high", "config_backup_exposed"),
    ("/config.php~", "high", "config_tilde_exposed"),
    ("/wp-config.php.bak", "high", "wp_config_backup_exposed"),
    ("/backup.zip", "high", "backup_zip_exposed"),
    ("/backup.tar.gz", "high", "backup_targz_exposed"),
    ("/backup.sql", "critical", "backup_sql_exposed"),
    ("/db.sql", "critical", "db_sql_exposed"),
    ("/dump.sql", "critical", "dump_sql_exposed"),
    ("/.DS_Store", "low", "ds_store_exposed"),
    ("/.htaccess", "medium", "htaccess_exposed"),
    ("/web.config", "medium", "web_config_exposed"),
    ("/phpinfo.php", "high", "phpinfo_exposed"),
    ("/info.php", "high", "info_php_exposed"),
    ("/test.php", "medium", "test_php_exposed"),
    ("/admin/", "low", "admin_panel_found"),
    ("/administrator/", "low", "admin_panel_found"),
    ("/wp-login.php", "low", "wp_login_found"),
    ("/swagger.json", "medium", "swagger_exposed"),
    ("/openapi.json", "medium", "openapi_exposed"),
    ("/api-docs", "medium", "api_docs_exposed"),
    ("/server-status", "medium", "server_status_exposed"),
    ("/crossdomain.xml", "low", "crossdomain_xml_found"),
]


BINARY_TYPES = {
    "backup_zip_exposed",
    "backup_targz_exposed",
}

PRESENCE_ONLY = {
    "admin_panel_found",
    "wp_login_found",
}


DETECT_SIGNATURES = {
    "git_config_exposed": ("[core]",),
    "git_head_exposed": ("ref:",),
    "env_file_exposed": ("DB_PASSWORD", "DB_HOST", "DB_NAME", "DB_USER", "APP_KEY", "APP_SECRET", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "SMTP_PASSWORD"),
    "env_local_exposed": ("DB_PASSWORD", "DB_HOST", "DB_NAME", "DB_USER", "APP_KEY", "APP_SECRET", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "SMTP_PASSWORD"),
    "env_production_exposed": ("DB_PASSWORD", "DB_HOST", "DB_NAME", "DB_USER", "APP_KEY", "APP_SECRET", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "SMTP_PASSWORD"),
    "env_backup_exposed": ("DB_PASSWORD", "DB_HOST", "DB_NAME", "DB_USER", "APP_KEY", "APP_SECRET", "SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "SMTP_PASSWORD"),
    "backup_sql_exposed": ("CREATE TABLE", "INSERT INTO", "-- MySQL"),
    "db_sql_exposed": ("CREATE TABLE", "INSERT INTO", "-- MySQL"),
    "dump_sql_exposed": ("CREATE TABLE", "INSERT INTO", "-- MySQL"),
    "phpinfo_exposed": ("phpinfo()", "PHP Version"),
    "info_php_exposed": ("phpinfo()", "PHP Version"),
    "svn_entries_exposed": ("<entry", "svn://", "dir\n"),
    "ds_store_exposed":      ("Bud1",),
    "htaccess_exposed":      ("<IfModule", "RewriteEngine", "Order ", "Require "),
    "web_config_exposed":    ("<configuration>", "<system.web>"),
    "config_backup_exposed": ("<?php", "<?=", "define(", "function "),
    "config_tilde_exposed":  ("<?php", "<?=", "define(", "function "),
    "wp_config_backup_exposed": ("DB_NAME", "DB_USER", "DB_PASSWORD", "<?php"),
    "test_php_exposed":      ("<?php", "phpinfo()", "PHP Version"),
    "swagger_exposed":       ('"swagger"', '"openapi"', '"paths"'),
    "openapi_exposed":       ('"openapi"', '"swagger"', '"paths"'),
    "crossdomain_xml_found": ("<cross-domain-policy>",),
}

async def check_host(session, base_url, timeout=6):
    findings = []
    base = base_url.rstrip("/")

    import uuid
    probe_path = f"__dynamo_probe_{uuid.uuid4().hex[:16]}__"
    catch_all = False
    try:
        async with session.get(
            base + "/" + probe_path, allow_redirects=False, timeout=timeout,
        ) as r:
            if r.status == 200:
                catch_all = True
    except Exception:
        pass

    async def probe(path, severity, vtype):
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            async with session.get(url, allow_redirects=False,
                                   timeout=timeout) as r:
                if r.status != 200:
                    return
                ct = (r.headers.get("Content-Type") or "").lower()

                body = await r.text(errors="replace")
                if len(body) > 500000:
                    body = body[:500000]

                if len(body) < 50:
                    return

                if vtype in PRESENCE_ONLY:
                    if catch_all:
                        return
                    findings.append({
                        "vuln_type": vtype,
                        "severity": severity,
                        "url": url,
                        "parameter": None,
                        "evidence": f"HTTP 200 for {path}",
                        "remediation": "Restrict access to admin/management areas",
                    })
                    return

                if vtype in BINARY_TYPES:
                    if "html" in ct:
                        return
                    findings.append({
                        "vuln_type": vtype,
                        "severity": severity,
                        "url": url,
                        "parameter": None,
                        "evidence": f"HTTP 200 for {path}",
                        "remediation": "Remove from web root or restrict access",
                    })
                    return

                sigs = DETECT_SIGNATURES.get(vtype)
                if not sigs:
                    return
                if not any(s in body for s in sigs):
                    return

                findings.append({
                    "vuln_type": vtype,
                    "severity": severity,
                    "url": url,
                    "parameter": None,
                    "evidence": f"HTTP 200 for {path}",
                    "remediation": "Remove from web root or restrict access",
                })
        except Exception:
            pass

    await asyncio.gather(*(probe(p, s, t) for p, s, t in PATHS),
                         return_exceptions=True)
    return findings
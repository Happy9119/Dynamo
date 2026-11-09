import os


class ArtifactWriter:
    def __init__(self, apex: str, scan_id: int, root: str = "runs"):
        self.apex = apex
        self.scan_id = scan_id
        self.dir = os.path.join(root, apex, str(scan_id))
        os.makedirs(self.dir, exist_ok=True)

    # ────────────────────────────────────────────────────────────────────
    def _w(self, relpath: str, lines) -> None:
        try:
            p = os.path.join(self.dir, relpath)
            parent = os.path.dirname(p)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                for line in (lines or []):
                    f.write(f"{line}\n")
        except Exception as e:
            print(f"  [!] artifact write failed ({relpath}): {e}")

    # ── Phase 1 ─────────────────────────────────────────────────────────
    def write_subfinder(self, subs):              self._w("subfinder_output.txt", subs)
    def write_crt(self, subs):                    self._w("crt_output.txt", subs)
    def write_gau(self, urls):                    self._w("gau_output.txt", urls)
    def write_wayback(self, urls):                self._w("wayback_output.txt", urls)
    def write_unique_subdomains(self, subs):      self._w("unique_subdomains.txt", subs)
    def write_unique_archive_urls(self, urls):    self._w("unique_archive_URLs.txt", urls)
    def write_live_archive_urls(self, urls):      self._w("live_archive_urls.txt", urls)

    # ── Phase 2 ─────────────────────────────────────────────────────────
    def write_httpx(self, httpx_results, assets):
        lines = []
        for r in httpx_results or []:
            url = r.get("url") or r.get("input") or ""
            if not url:
                continue
            lines.append(
                f"{url} "
                f"[{r.get('status_code', '')}] "
                f"[{r.get('host_ip') or r.get('ip') or ''}] "
                f"[{r.get('title') or ''}]"
            )
        self._w("httpx_output.txt", lines)

        # Derive the other three
        live = sorted({r.get("url") or r.get("input")
                       for r in httpx_results or []
                       if (r.get("url") or r.get("input"))})
        ip_map, ips = [], set()
        for a in assets or []:
            url = a.url or a.asset_value
            for ip in a.resolved_ips or []:
                ip_map.append(f"{url}\t{ip}")
                ips.add(ip)
        self._w("live_subdomains.txt", live)
        self._w("subdomain_ip_map.txt", ip_map)
        self._w("unique_ips.txt", sorted(ips))

    # ── Phase 3 ─────────────────────────────────────────────────────────
    def write_nmap_merged(self, nmap_dir, ips):
        parts = []
        for ip in sorted(ips or []):
            p = os.path.join(nmap_dir, f"{ip}.txt")
            if os.path.exists(p):
                try:
                    with open(p, "r", errors="replace") as f:
                        parts.append(f.read())
                except Exception:
                    pass
        self._w("nmap_output.txt", ["\n".join(parts)] if parts else [])

    # ── Phase 4 / 5 ─────────────────────────────────────────────────────
    def write_katana(self, urls):                 self._w("crawling/katana_output.txt", urls)
    def write_param_urls(self, urls):             self._w("urls_with_params.txt", urls)
    def write_ffuf(self, urls):                   self._w("dirfuzz_results.txt", urls)

    # ── Phase 6 — Nuclei ────────────────────────────────────────────────
    @staticmethod
    def _fmt_nuclei(f: dict) -> str:
        info = f.get("info", {}) or {}
        return (
            f"[{f.get('template-id') or f.get('template_id') or ''}] "
            f"[{info.get('severity') or f.get('severity') or ''}] "
            f"{f.get('matched-at') or f.get('matched_at') or ''}"
        )

    def write_nuclei_urls(self, findings):
        self._w("nuclei_output_urls.txt", [self._fmt_nuclei(f) for f in findings or []])

    def write_nuclei_ips(self, findings):
        self._w("nuclei_output_ips.txt", [self._fmt_nuclei(f) for f in findings or []])

    # ── Phase 6.5 — JS ──────────────────────────────────────────────────
    def write_js(self, js_urls, findings, unique_lines):
        self._w("js_urls.txt", js_urls or [])
        self._w("js_secret_findings.txt", unique_lines or [])
        self._w("js_secrets_unique.txt", sorted(set(unique_lines or [])))

    # ── Phase 6.6 / 6.7 — VAPT findings ─────────────────────────────────
    def write_vapt(self, findings):
        lines = [
            f"[{f.get('severity', '')}] {f.get('vuln_type', '')} @ {f.get('url', '')}"
            + (f" (param={f.get('parameter')})" if f.get("parameter") else "")
            for f in findings or []
        ]
        self._w("vapt_findings.txt", lines)

    # ── Phase 7 — SQLMap ────────────────────────────────────────────────
    def write_sqlmap(self, tested_urls, vuln_findings):
        vuln_findings = [v for v in (vuln_findings or [])
                         if v.get("vulnerable") and v.get("url")]

        self._w("sqlmap_tested.txt", sorted(set(tested_urls or [])))
        self._w("sqlmap_confirmed_candidates.txt", [v["url"] for v in vuln_findings])
        summary = [
            f"{v['url']}\t|\tType: {v.get('technique') or 'unknown'}"
            f"\t|\tPayload: {v.get('payload') or 'unknown'}"
            for v in vuln_findings
        ]
        self._w("sqlmap_vuln_summary.txt", summary)
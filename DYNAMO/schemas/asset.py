from typing import List, Optional
from pydantic import BaseModel, Field, AliasChoices

class AttackPathStep(BaseModel):
    step_number: int = Field(...)
    title: str = Field(default="Exploitation Step")
    description: str = Field(default="")
    target_component: Optional[str] = Field(default="")


class SuggestedReconAction(BaseModel):
    purpose: str = Field(default="")
    tool_command: str = Field(default="")


class AIIntelligence(BaseModel):
    exploitability_tier: str = Field(default="Medium")
    exploitability_score: int = Field(default=50)
    attack_vector_summary: str = Field(default="")
    attack_path: List[AttackPathStep] = Field(default_factory=list)
    mitigation_priority: List[str] = Field(default_factory=list)
    suggested_recon_actions: List[SuggestedReconAction] = Field(default_factory=list)


class Service(BaseModel):
    port: int
    protocol: str
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    webserver: Optional[str] = None
    technologies: List[str] = []


class NucleiFinding(BaseModel):
    template_id: Optional[str] = None
    name: Optional[str] = None
    severity: Optional[str] = None
    matched_at: Optional[str] = None
    host: Optional[str] = None
    description: Optional[str] = None
    reference: List[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class SQLiFinding(BaseModel):
    url: str
    vulnerable: bool = False
    technique: Optional[str] = None
    payload: Optional[str] = None


class VulnFinding(BaseModel):
    vuln_type: str
    severity: str
    url: str
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class Asset(BaseModel):
    asset_value: str
    resolved_ips: List[str] = []

    url: Optional[str] = None
    title: Optional[str] = None
    status_code: Optional[int] = None
    cdn_name: Optional[str] = None

    technologies: List[str] = Field(default_factory=list)
    services: List[Service] = Field(default_factory=list)

    historical_urls:  List[str] = Field(default_factory=list)
    live_urls:        List[str] = Field(default_factory=list)
    crawled_urls:     List[str] = Field(default_factory=list)
    parameter_urls:   List[str] = Field(default_factory=list)
    discovered_paths: List[str] = Field(default_factory=list)
    js_endpoints:     List[str] = Field(default_factory=list)
    nuclei_findings:  List[NucleiFinding] = Field(default_factory=list)
    sqli_findings:    List[SQLiFinding] = Field(default_factory=list)
    vulns:            List[VulnFinding] = Field(default_factory=list)

    risk_score: int = 0
    risk_summary: Optional[str] = None
    cves: List[dict] = Field(default_factory=list)

    ai_analysis: Optional[AIIntelligence] = None


class AIResult(BaseModel):
    status: str
    model: Optional[str] = None
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    intelligence: Optional[AIIntelligence] = None
"""ORM models for persisted analyses."""
from __future__ import annotations

import json
from datetime import datetime
from typing   import Any, Dict, List

from sqlalchemy        import (Column, DateTime, Float, ForeignKey, Integer,
                                String, Text, Index)
from sqlalchemy.orm    import declarative_base, relationship

Base = declarative_base()


class Analysis(Base):
    __tablename__ = "analyses"

    id                = Column(Integer, primary_key=True)
    analysis_id       = Column(String(32), unique=True, nullable=False, index=True)
    filename          = Column(String(512), nullable=False)
    filetype          = Column(String(128))
    size_bytes        = Column(Integer)

    md5               = Column(String(32),  index=True)
    sha1              = Column(String(40),  index=True)
    sha256            = Column(String(64),  index=True)

    verdict           = Column(String(32),  index=True)        # malicious/suspicious/benign
    severity          = Column(String(32),  index=True)
    confidence        = Column(Float)
    static_risk_score = Column(Integer)
    ml_probability    = Column(Float)
    malware_family    = Column(String(128))
    ai_provider       = Column(String(64))

    elapsed_seconds   = Column(Float)
    created_at        = Column(DateTime, default=datetime.utcnow,
                                index=True, nullable=False)

    # Full JSON dossier kept for /api/analysis/<id> + reproducibility
    payload_json      = Column(Text)

    iocs              = relationship("IOCRecord",  back_populates="analysis",
                                     cascade="all, delete-orphan")
    mitre             = relationship("MitreHit",   back_populates="analysis",
                                     cascade="all, delete-orphan")
    chat_messages     = relationship("ChatMessage", back_populates="analysis",
                                     cascade="all, delete-orphan",
                                     order_by="ChatMessage.created_at")

    def to_summary(self) -> Dict[str, Any]:
        return {
            "analysis_id":       self.analysis_id,
            "filename":          self.filename,
            "filetype":          self.filetype,
            "size_bytes":        self.size_bytes,
            "sha256":            self.sha256,
            "verdict":           self.verdict,
            "severity":          self.severity,
            "confidence":        self.confidence,
            "static_risk_score": self.static_risk_score,
            "ml_probability":    self.ml_probability,
            "malware_family":    self.malware_family,
            "ai_provider":       self.ai_provider,
            "elapsed_seconds":   self.elapsed_seconds,
            "created_at":        self.created_at.isoformat() + "Z",
            "ioc_total":         len(self.iocs or []),
            "mitre_count":       len(self.mitre or []),
        }


class IOCRecord(Base):
    __tablename__ = "iocs"

    id          = Column(Integer, primary_key=True)
    analysis_pk = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"),
                         nullable=False)
    kind        = Column(String(32), nullable=False, index=True)   # url/domain/ipv4/...
    value       = Column(String(1024), nullable=False)

    analysis    = relationship("Analysis", back_populates="iocs")


class MitreHit(Base):
    __tablename__ = "mitre_hits"

    id           = Column(Integer, primary_key=True)
    analysis_pk  = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"),
                          nullable=False)
    technique_id = Column(String(32),  nullable=False, index=True)
    name         = Column(String(256))
    tactic       = Column(String(128), index=True)
    evidence     = Column(Text)

    analysis     = relationship("Analysis", back_populates="mitre")


class ChatMessage(Base):
    """Persisted chat-with-analyst conversation, scoped to one analysis."""
    __tablename__ = "chat_messages"

    id           = Column(Integer, primary_key=True)
    analysis_pk  = Column(Integer, ForeignKey("analyses.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    role         = Column(String(16), nullable=False)            # "user" | "assistant"
    content      = Column(Text,        nullable=False)
    provider     = Column(String(64))                            # which LLM answered
    created_at   = Column(DateTime, default=datetime.utcnow,
                          nullable=False, index=True)

    analysis     = relationship("Analysis", back_populates="chat_messages")


# composite indexes for the common queries on the history page
Index("ix_analyses_verdict_created", Analysis.verdict, Analysis.created_at.desc())
Index("ix_iocs_kind_value",          IOCRecord.kind,   IOCRecord.value)


# --------- helpers --------------------------------------------------------

def from_payload(session, payload: Dict[str, Any]) -> Analysis:
    """Persist a complete analysis payload returned by the orchestrator."""
    static = payload["static"]
    ml     = payload["ml"]
    ai     = payload["ai"]
    iocs   = payload["iocs"]
    mitre  = payload["mitre"]

    h = static.get("hashes", {}) or {}
    row = Analysis(
        analysis_id       = payload["analysis_id"],
        filename          = static.get("filename"),
        filetype          = static.get("filetype"),
        size_bytes        = int(static.get("size_bytes", 0)),
        md5               = h.get("md5"),
        sha1              = h.get("sha1"),
        sha256            = h.get("sha256"),
        verdict           = (ai.get("verdict")  or "unknown"),
        severity          = (ai.get("severity") or "unknown"),
        confidence        = float(ai.get("confidence", 0) or 0),
        static_risk_score = int(static.get("static_risk_score", 0) or 0),
        ml_probability    = float(ml.get("malicious_probability") or 0)
                            if ml.get("malicious_probability") is not None else None,
        malware_family    = (ai.get("malware_family") or "")[:128],
        ai_provider       = (ai.get("_provider") or "")[:64],
        elapsed_seconds   = float(payload.get("elapsed_seconds", 0) or 0),
        payload_json      = json.dumps(payload, default=str),
    )

    # IOCs
    for kind, items in (iocs or {}).items():
        for v in (items or []):
            row.iocs.append(IOCRecord(kind=kind, value=str(v)[:1024]))

    # MITRE
    for m in (mitre or []):
        row.mitre.append(MitreHit(
            technique_id = (m.get("id")     or "")[:32],
            name         = (m.get("name")   or "")[:256],
            tactic       = (m.get("tactic") or "")[:128],
            evidence     = (m.get("evidence") or ""),
        ))

    session.add(row)
    return row


def list_recent(session, limit: int = 50, verdict: str | None = None
                ) -> List[Analysis]:
    q = session.query(Analysis).order_by(Analysis.created_at.desc())
    if verdict:
        q = q.filter(Analysis.verdict == verdict)
    return q.limit(limit).all()


def get_by_aid(session, aid: str) -> Analysis | None:
    return session.query(Analysis).filter(Analysis.analysis_id == aid).one_or_none()


def list_chat(session, analysis_pk: int) -> List["ChatMessage"]:
    return (session.query(ChatMessage)
                   .filter(ChatMessage.analysis_pk == analysis_pk)
                   .order_by(ChatMessage.created_at.asc()).all())


def add_chat(session, analysis_pk: int, role: str, content: str,
             provider: str | None = None) -> "ChatMessage":
    msg = ChatMessage(analysis_pk=analysis_pk, role=role,
                      content=content, provider=(provider or "")[:64])
    session.add(msg)
    return msg


def clear_chat(session, analysis_pk: int) -> int:
    n = (session.query(ChatMessage)
                .filter(ChatMessage.analysis_pk == analysis_pk).delete())
    return int(n or 0)


def stats(session) -> Dict[str, int]:
    from sqlalchemy import func
    rows = (session.query(Analysis.verdict, func.count(Analysis.id))
                  .group_by(Analysis.verdict).all())
    out = {"total": 0}
    for v, c in rows:
        out[v or "unknown"] = c
        out["total"] += c
    return out

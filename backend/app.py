"""Flask application — orchestrates upload → analysis → DB → report."""
from __future__ import annotations

import json
import time
import traceback
import uuid
from pathlib import Path

from flask          import Flask, jsonify, request, send_file, send_from_directory
from flask_cors     import CORS
from werkzeug.utils import secure_filename

import config
import db
from db                import models as dbm
from analyzers         import (ai_analyzer, ioc_extractor, ml_classifier,
                                mitre_mapper, static_analyzer)
from reports           import pdf_generator
from utils.file_utils  import extract_strings


def create_app() -> Flask:
    app = Flask(__name__,
                static_folder=str(config.FRONTEND_DIR),
                static_url_path="")
    CORS(app)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024

    # bootstrap DB on app creation
    try:
        db.init_engine()
    except Exception as e:                                              # noqa: BLE001
        print(f"[WARN] Database initialisation failed: {e}")

    # auto-train the ML model on first boot (handles ephemeral disks
    # like Render / Railway free tiers where the build artefact disappears)
    if not Path(config.MODEL_PATH).exists():
        try:
            print("[bootstrap] ML model missing — training now …")
            from ml_models import train_model
            train_model.main()
        except Exception as e:                                          # noqa: BLE001
            print(f"[WARN] ML model training failed: {e}")

    # ----- frontend ----------------------------------------------------
    @app.get("/")
    def index():
        return send_from_directory(str(config.FRONTEND_DIR), "index.html")

    @app.get("/analysis.html")
    def analysis_page():
        return send_from_directory(str(config.FRONTEND_DIR), "analysis.html")

    @app.get("/history.html")
    def history_page():
        return send_from_directory(str(config.FRONTEND_DIR), "history.html")

    # ----- API ---------------------------------------------------------
    @app.get("/api/health")
    def health():
        try:
            with db.session_scope() as s:
                stats = dbm.stats(s)
        except Exception as e:                                          # noqa: BLE001
            stats = {"error": str(e)}
        return jsonify({
            "status":       "ok",
            "provider":     config.llm_provider(),
            "model_loaded": config.MODEL_PATH.exists(),
            "version":      "1.1.0",
            "db":           {**db.info(), "stats": stats},
        })

    @app.post("/api/analyze")
    def analyze():
        if "file" not in request.files:
            return jsonify({"error": "No 'file' field in multipart payload"}), 400
        f = request.files["file"]
        if not f or not f.filename:
            return jsonify({"error": "Empty filename"}), 400

        analysis_id = uuid.uuid4().hex[:12]
        safe_name   = secure_filename(f.filename) or f"sample_{analysis_id}"
        save_path   = Path(config.UPLOAD_DIR) / f"{analysis_id}_{safe_name}"
        f.save(save_path)

        t0 = time.time()
        try:
            # 1. Static analysis
            static_data = static_analyzer.analyze(save_path)

            # 2. IOC extraction
            iocs = ioc_extractor.extract(extract_strings(save_path))
            static_data["ioc_count"] = sum(len(v) for v in iocs.values())

            # 3. ML classifier
            ml_data = ml_classifier.predict(static_data)

            # 4. AI / LLM investigation
            ai_data = ai_analyzer.investigate(static_data, ml_data, iocs)

            # 5. Merge MITRE coverage
            mitre_static = mitre_mapper.map_static(static_data)
            mitre = mitre_mapper.merge(mitre_static, ai_data.get("mitre", []))

            elapsed = round(time.time() - t0, 3)
            payload = {
                "analysis_id":     analysis_id,
                "elapsed_seconds": elapsed,
                "static":          static_data,
                "ml":              ml_data,
                "iocs":            iocs,
                "ai":              ai_data,
                "mitre":           mitre,
                "report_url":      f"/api/report/{analysis_id}",
            }

            # 6. Persist to DB
            try:
                with db.session_scope() as s:
                    dbm.from_payload(s, payload)
                payload["persisted"] = True
            except Exception as e:                                      # noqa: BLE001
                print(f"[WARN] DB persist failed: {e}")
                payload["persisted"] = False
                payload["db_error"]  = str(e)

            # 7. Cache JSON on disk (still useful for debugging)
            (Path(config.ANALYSIS_CACHE) / f"{analysis_id}.json").write_text(
                json.dumps(payload, indent=2, default=str), encoding="utf-8"
            )

            # 8. PDF report
            pdf_path = pdf_generator.generate(payload)
            payload["report_path"] = str(pdf_path)

            return jsonify(payload)

        except Exception as e:                                          # noqa: BLE001
            traceback.print_exc()
            return jsonify({
                "error":         str(e),
                "analysis_id":   analysis_id,
                "trace_summary": traceback.format_exc().splitlines()[-3:],
            }), 500

    @app.get("/api/analysis/<aid>")
    def get_analysis(aid: str):
        # Try DB first
        try:
            with db.session_scope() as s:
                row = dbm.get_by_aid(s, aid)
                if row and row.payload_json:
                    return app.response_class(row.payload_json,
                                              mimetype="application/json")
        except Exception:
            pass
        # Disk cache fallback
        p = Path(config.ANALYSIS_CACHE) / f"{aid}.json"
        if not p.exists():
            return jsonify({"error": "not found"}), 404
        return send_file(p, mimetype="application/json")

    @app.get("/api/report/<aid>")
    def get_report(aid: str):
        p = Path(config.REPORT_DIR) / f"{aid}.pdf"
        if not p.exists():
            return jsonify({"error": "report not found"}), 404
        return send_file(p, mimetype="application/pdf",
                         as_attachment=False,
                         download_name=f"AssemblyAI_Report_{aid}.pdf")

    @app.get("/api/history")
    def history():
        verdict = request.args.get("verdict") or None
        limit   = min(int(request.args.get("limit", "50")), 500)
        try:
            with db.session_scope() as s:
                rows = dbm.list_recent(s, limit=limit, verdict=verdict)
                items = [r.to_summary() for r in rows]
                return jsonify({
                    "items": items,
                    "count": len(items),
                    "stats": dbm.stats(s),
                    "db":    db.info(),
                })
        except Exception as e:                                          # noqa: BLE001
            return jsonify({"error": str(e), "items": []}), 500

    @app.get("/api/iocs/<kind>")
    def all_iocs(kind: str):
        try:
            with db.session_scope() as s:
                rows = (s.query(dbm.IOCRecord.value, dbm.IOCRecord.analysis_pk)
                          .filter(dbm.IOCRecord.kind == kind)
                          .distinct().limit(500).all())
                return jsonify({"kind": kind,
                                "values": sorted({r[0] for r in rows})})
        except Exception as e:                                          # noqa: BLE001
            return jsonify({"error": str(e), "values": []}), 500

    # ----- Conversational analyst -------------------------------------
    @app.get("/api/chat/<aid>")
    def get_chat(aid: str):
        """Return the stored conversation for an analysis."""
        try:
            with db.session_scope() as s:
                row = dbm.get_by_aid(s, aid)
                if not row:
                    return jsonify({"error": "analysis not found"}), 404
                msgs = [{
                    "role":       m.role,
                    "content":    m.content,
                    "provider":   m.provider,
                    "created_at": m.created_at.isoformat() + "Z",
                } for m in dbm.list_chat(s, row.id)]
                return jsonify({"analysis_id": aid, "messages": msgs})
        except Exception as e:                                          # noqa: BLE001
            return jsonify({"error": str(e), "messages": []}), 500

    @app.post("/api/chat/<aid>")
    def post_chat(aid: str):
        """Send a user message; get the assistant reply (and persist both)."""
        body     = request.get_json(silent=True) or {}
        user_msg = (body.get("message") or "").strip()
        if not user_msg:
            return jsonify({"error": "empty message"}), 400
        if len(user_msg) > 4000:
            return jsonify({"error": "message too long (max 4000 chars)"}), 400

        # 1. Load dossier + history, persist the user turn
        try:
            with db.session_scope() as s:
                row = dbm.get_by_aid(s, aid)
                if not row or not row.payload_json:
                    return jsonify({"error": "analysis not found"}), 404
                dossier = json.loads(row.payload_json)
                history = [{"role": m.role, "content": m.content}
                           for m in dbm.list_chat(s, row.id)]
                history.append({"role": "user", "content": user_msg})
                dbm.add_chat(s, row.id, "user", user_msg)
                analysis_pk = row.id
        except Exception as e:                                          # noqa: BLE001
            return jsonify({"error": f"load failed: {e}"}), 500

        # 2. Call the LLM (outside the DB transaction)
        result = ai_analyzer.chat(dossier, history)

        # 3. Persist the assistant turn
        try:
            with db.session_scope() as s:
                dbm.add_chat(s, analysis_pk, "assistant",
                             result.get("response", ""), result.get("provider"))
        except Exception as e:                                          # noqa: BLE001
            print(f"[WARN] chat persist failed: {e}")

        return jsonify({
            "analysis_id": aid,
            "response":    result.get("response", ""),
            "provider":    result.get("provider"),
        })

    @app.delete("/api/chat/<aid>")
    def delete_chat(aid: str):
        try:
            with db.session_scope() as s:
                row = dbm.get_by_aid(s, aid)
                if not row:
                    return jsonify({"error": "not found"}), 404
                n = dbm.clear_chat(s, row.id)
            return jsonify({"ok": True, "deleted": n})
        except Exception as e:                                          # noqa: BLE001
            return jsonify({"error": str(e)}), 500

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": f"File exceeds {config.MAX_UPLOAD_MB} MB limit"}), 413

    return app


if __name__ == "__main__":
    create_app().run(host=config.FLASK_HOST,
                     port=config.FLASK_PORT,
                     debug=config.FLASK_DEBUG)

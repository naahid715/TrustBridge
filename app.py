from __future__ import annotations
from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime
from typing import Dict, List
import uuid

from crypto_utils import ensure_keys, encrypt_record, judge_decrypt_share, govt_decrypt_and_reveal

app = Flask(__name__)
app.secret_key = "dev-secret"

ensure_keys()

data_records: List[Dict] = []
access_requests: List[Dict] = []
audit_logs: List[Dict] = []

def log(action: str, who: str, details: str):
    audit_logs.append({
        "time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "action": action,
        "who": who,
        "details": details
    })


@app.route("/")
def home():
    return render_template("home.html",
                           total_records=len(data_records),
                           pending=len([r for r in access_requests if r["status"] == "pending"]),
                           approved=len([r for r in access_requests if r["status"] == "judge_approved"]),
                           completed=len([r for r in access_requests if r["status"] == "completed"]),
                           )



@app.route("/citizen", methods=["GET", "POST"])
def citizen():
    if request.method == "POST":
        citizen_name = request.form.get("citizen_name", "").strip() or "Anonymous"
        message = request.form.get("message", "").encode()

        payload = encrypt_record(message)
        record_id = str(uuid.uuid4())
        data_records.append({
            "id": record_id,
            "citizen": citizen_name,
            "submitted_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "payload": payload,
        })
        log("citizen_upload", citizen_name, f"record_id={record_id}")
        flash("Data submitted and securely encrypted.", "success")
        return redirect(url_for("citizen"))

    return render_template("citizen.html", records=list(reversed(data_records)))



@app.route("/govt", methods=["GET"])
def govt():
    return render_template("govt.html",
                           records=list(reversed(data_records)),
                           reqs=list(reversed(access_requests)))


@app.route("/govt/request/<record_id>", methods=["POST"])
def govt_request(record_id):
    who = request.form.get("govt_name", "AgentX")
    req_id = str(uuid.uuid4())
    access_requests.append({
        "id": req_id,
        "record_id": record_id,
        "who": who,
        "status": "pending",
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "judge_share_raw": None,
    })
    log("govt_request", who, f"req_id={req_id} for record_id={record_id}")
    flash("Request submitted for judge approval.", "info")
    return redirect(url_for("govt"))


@app.route("/govt/view/<req_id>", methods=["GET"])
def govt_view(req_id):
    req = next((r for r in access_requests if r["id"] == req_id), None)
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("govt"))

    if req["status"] != "judge_approved" or req["judge_share_raw"] is None:
        flash("Judge approval required before viewing.", "warning")
        return redirect(url_for("govt"))

    record = next((d for d in data_records if d["id"] == req["record_id"]), None)
    if not record:
        flash("Record not found.", "danger")
        return redirect(url_for("govt"))

    try:
        plaintext = govt_decrypt_and_reveal(record["payload"], req["judge_share_raw"]).decode()
    except Exception as e:
        flash(f"Decryption failed: {e}", "danger")
        return redirect(url_for("govt"))

    req["status"] = "completed"
    log("govt_view", req["who"], f"req_id={req_id} decrypted record_id={req['record_id']}")
    return render_template("view.html", message=plaintext, record=record, req=req)



@app.route("/judge", methods=["GET"])
def judge():
    pend = [r for r in access_requests if r["status"] == "pending"]
    return render_template("judge.html", pending=list(reversed(pend)))


@app.route("/judge/approve/<req_id>", methods=["POST"])
def judge_approve(req_id):
    req = next((r for r in access_requests if r["id"] == req_id), None)
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("judge"))

    record = next((d for d in data_records if d["id"] == req["record_id"]), None)
    if not record:
        flash("Record not found.", "danger")
        return redirect(url_for("judge"))

    judge_share = judge_decrypt_share(record["payload"]["enc_share_judge_b64"])
    req["judge_share_raw"] = judge_share
    req["status"] = "judge_approved"
    log("judge_approve", "Judge", f"req_id={req_id}")
    flash("Approved. Govt can now complete decryption.", "success")
    return redirect(url_for("judge"))


@app.route("/judge/deny/<req_id>", methods=["POST"])
def judge_deny(req_id):
    req = next((r for r in access_requests if r["id"] == req_id), None)
    if not req:
        flash("Request not found.", "danger")
        return redirect(url_for("judge"))
    req["status"] = "denied"
    log("judge_deny", "Judge", f"req_id={req_id}")
    flash("Request denied.", "warning")
    return redirect(url_for("judge"))



@app.route("/logs")
def logs():
    return render_template("logs.html", logs=list(reversed(audit_logs)))


if __name__ == "__main__":
    app.run(debug=True)

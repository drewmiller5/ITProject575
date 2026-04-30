from flask import Flask, request, jsonify, render_template
from database import init_db, create_user, get_user, save_credential, get_credential, get_credentials_by_user, log_login_event, get_login_history, save_security_questions, get_security_questions, verify_security_answers, lock_user, is_user_locked, increment_failed_attempts, reset_failed_attempts, LOCK_DURATION_HOURS, update_security_questions, delete_all_security_questions, normalize_answer, save_recovery, get_recovery, verify_recovery, get_db
from risk_engine import score_login
import random

app = Flask(__name__)

init_db()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    questions_and_answers = data.get("security_questions", [])
    recovery_type = data.get("recovery_type", "pin")
    recovery_value = data.get("recovery_value", "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if len(questions_and_answers) != 3:
        return jsonify({"error": "You must set exactly 3 security questions"}), 400

    if not recovery_value:
        return jsonify({"error": "A recovery PIN or passphrase is required"}), 400

    if recovery_type == "pin" and (not recovery_value.isdigit() or len(recovery_value) < 4):
        return jsonify({"error": "PIN must be at least 4 digits"}), 400

    if recovery_type == "phrase" and len(recovery_value) < 5:
        return jsonify({"error": "Passphrase must be at least 5 characters"}), 400

    success = create_user(username)
    if not success:
        return jsonify({"error": "Username already exists"}), 409

    user = get_user(username)
    credential_id = f"cred-{username}-{user['id']}"
    save_credential(user["id"], credential_id)

    pairs = [(q["question"], q["answer"]) for q in questions_and_answers]
    save_security_questions(user["id"], pairs)

    save_recovery(user["id"], recovery_type, recovery_value)

    return jsonify({
        "message": f"User {username} registered successfully",
        "credential_id": credential_id
    }), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    credential_id = data.get("credential_id", "").strip()

    if not username or not credential_id:
        return jsonify({"error": "Username and credential_id are required"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if is_user_locked(user["id"]):
        return jsonify({
            "error": f"Account locked due to too many failed attempts. Please try again in {LOCK_DURATION_HOURS} hours or use account recovery."
        }), 403

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "unknown")
    risk = score_login(user["id"], ip, ua)

    log_login_event(user["id"], ip, ua, risk["score"], risk["decision"])

    all_questions = get_security_questions(user["id"])

    if risk["decision"] == "allowed":
        return jsonify({
            "message": f"Welcome {username}",
            "risk": risk
        }), 200

    shuffled = list(all_questions)
    random.shuffle(shuffled)

    if risk["decision"] == "challenged_1":
        return jsonify({
            "message": "Additional verification required",
            "risk": risk,
            "questions": [{"question": shuffled[0]["question"]}]
        }), 200

    if risk["decision"] == "challenged_2":
        return jsonify({
            "message": "Additional verification required",
            "risk": risk,
            "questions": [
                {"question": shuffled[0]["question"]},
                {"question": shuffled[1]["question"]}
            ]
        }), 200

    if risk["decision"] == "challenged_3":
        return jsonify({
            "message": "Additional verification required",
            "risk": risk,
            "questions": [
                {"question": shuffled[0]["question"]},
                {"question": shuffled[1]["question"]},
                {"question": shuffled[2]["question"]}
            ]
        }), 200

    return jsonify({"error": "Unexpected risk decision"}), 500

@app.route("/challenge", methods=["POST"])
def challenge():
    data = request.get_json()
    username = data.get("username", "").strip()
    answers = data.get("answers", [])
    escalation_level = data.get("escalation_level", 1)

    if not username or not answers:
        return jsonify({"error": "Username and answers are required"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "unknown")

    all_questions = get_security_questions(user["id"])
    stored = {row["question"]: row["answer"] for row in all_questions}

    passed_answers = []
    failed_answers = []
    for a in answers:
        expected = stored.get(a["question"], "")
        if normalize_answer(a["answer"]) == normalize_answer(expected):
            passed_answers.append(a)
        else:
            failed_answers.append(a)

    passed = len(passed_answers)
    total = len(answers)

    if passed == 0:
        now_locked = increment_failed_attempts(user["id"])
        log_login_event(user["id"], ip, ua, 100, "blocked")
        if now_locked:
            return jsonify({
                "success": False,
                "blocked": True,
                "message": f"Access denied — failed all questions. Account locked for {LOCK_DURATION_HOURS} hours."
            }), 401
        return jsonify({
            "success": False,
            "blocked": True,
            "message": "Access denied — failed all questions."
        }), 401

    if passed == total:
        log_login_event(user["id"], ip, ua, 0, "allowed")
        reset_failed_attempts(user["id"])
        return jsonify({
            "success": True,
            "message": f"Welcome {username}"
        }), 200

    locked = [{"question": a["question"], "answer": a["answer"], "locked": True} for a in passed_answers]
    asked_questions = {a["question"] for a in answers}
    remaining = [q for q in all_questions if q["question"] not in asked_questions]

    if escalation_level < 3 and remaining:
        next_question = random.choice(remaining)
        next_level = escalation_level + 1
        return jsonify({
            "success": False,
            "escalate": True,
            "escalation_level": next_level,
            "message": f"Got {passed} of {total} correct — answer one more question.",
            "previous_answers": locked,
            "new_question": {"question": next_question["question"], "locked": False}
        }), 200

    if escalation_level == 3 and len(failed_answers) == 1:
        return jsonify({
            "success": False,
            "retry": True,
            "escalation_level": 3,
            "message": "One question incorrect — one final attempt.",
            "previous_answers": locked,
            "retry_question": {"question": failed_answers[0]["question"], "locked": False}
        }), 200

    now_locked = increment_failed_attempts(user["id"])
    log_login_event(user["id"], ip, ua, 100, "blocked")
    if now_locked:
        return jsonify({
            "success": False,
            "blocked": True,
            "message": f"Access denied — too many incorrect answers. Account locked for {LOCK_DURATION_HOURS} hours."
        }), 401
    return jsonify({
        "success": False,
        "blocked": True,
        "message": "Access denied — too many incorrect answers."
    }), 401

@app.route("/questions/get", methods=["POST"])
def get_questions():
    data = request.get_json()
    username = data.get("username", "").strip()
    credential_id = data.get("credential_id", "").strip()

    if not username or not credential_id:
        return jsonify({"error": "Username and credential_id are required"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if is_user_locked(user["id"]):
        return jsonify({"error": f"Account locked for {LOCK_DURATION_HOURS} hours."}), 403

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    questions = get_security_questions(user["id"])
    return jsonify({
        "questions": [{"question": q["question"]} for q in questions]
    }), 200

@app.route("/questions/change", methods=["POST"])
def change_questions():
    data = request.get_json()
    username        = data.get("username", "").strip()
    credential_id   = data.get("credential_id", "").strip()
    current_answers = data.get("current_answers", [])
    new_questions   = data.get("new_questions", [])

    if not username or not credential_id:
        return jsonify({"error": "username and credential_id are required"}), 400

    if not current_answers:
        return jsonify({"error": "current_answers are required to verify your identity"}), 400

    if not new_questions:
        return jsonify({"error": "new_questions must contain at least one entry"}), 400

    if len(new_questions) > 3:
        return jsonify({"error": "You can only set up to 3 security questions"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if is_user_locked(user["id"]):
        return jsonify({
            "error": f"Account locked. Please try again in {LOCK_DURATION_HOURS} hours or contact support."
        }), 403

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    stored_rows = get_security_questions(user["id"])
    stored = {row["question"]: row["answer"] for row in stored_rows}

    failed = []
    for a in current_answers:
        expected = stored.get(a["question"], "")
        if normalize_answer(a["answer"]) != normalize_answer(expected):
            failed.append(a["question"])

    if failed:
        now_locked = increment_failed_attempts(user["id"])
        if now_locked:
            return jsonify({
                "error": f"Too many failed attempts. Account locked for {LOCK_DURATION_HOURS} hours.",
                "locked": True
            }), 403
        return jsonify({
            "error": "One or more current answers were incorrect.",
            "failed_questions": failed
        }), 401

    reset_failed_attempts(user["id"])
    update_security_questions(user["id"], new_questions)

    changed = [q["question"] for q in new_questions]
    return jsonify({
        "message": "Security question(s) updated successfully.",
        "updated": changed
    }), 200

@app.route("/questions/recover", methods=["POST"])
def recover_questions():
    data = request.get_json()
    username      = data.get("username", "").strip()
    credential_id = data.get("credential_id", "").strip()
    new_questions = data.get("new_questions", [])

    if not username or not credential_id:
        return jsonify({"error": "username and credential_id are required"}), 400

    if len(new_questions) != 3:
        return jsonify({"error": "You must provide exactly 3 new security questions for recovery"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    delete_all_security_questions(user["id"])
    pairs = [(q["question"], q["answer"]) for q in new_questions]
    save_security_questions(user["id"], pairs)

    if is_user_locked(user["id"]):
        with get_db() as db:
            db.execute(
                "UPDATE users SET locked = 0, locked_until = NULL, failed_attempts = 0 WHERE id = ?",
                (user["id"],)
            )
            db.commit()

    return jsonify({
        "message": "Security questions reset successfully. You can now log in normally."
    }), 200

@app.route("/recovery/verify", methods=["POST"])
def recovery_verify():
    data = request.get_json()
    username = data.get("username", "").strip()
    credential_id = data.get("credential_id", "").strip()
    recovery_value = data.get("recovery_value", "").strip()

    if not username or not credential_id or not recovery_value:
        return jsonify({"error": "Username, credential_id and recovery value are required"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    if not verify_recovery(user["id"], recovery_value):
        return jsonify({"error": "Incorrect recovery PIN or passphrase"}), 401

    with get_db() as db:
        db.execute(
            "UPDATE users SET locked = 0, locked_until = NULL, failed_attempts = 0 WHERE id = ?",
            (user["id"],)
        )
        db.commit()

    delete_all_security_questions(user["id"])

    return jsonify({
        "success": True,
        "message": "Account unlocked. Please set new security questions to continue."
    }), 200

@app.route("/recovery/change", methods=["POST"])
def recovery_change():
    data = request.get_json()
    username = data.get("username", "").strip()
    credential_id = data.get("credential_id", "").strip()
    current_value = data.get("current_value", "").strip()
    new_value = data.get("new_value", "").strip()
    new_type = data.get("new_type", "").strip()

    if not all([username, credential_id, current_value, new_value, new_type]):
        return jsonify({"error": "All fields are required"}), 400

    if new_type == "pin" and (not new_value.isdigit() or len(new_value) < 4):
        return jsonify({"error": "PIN must be at least 4 digits"}), 400

    if new_type == "phrase" and len(new_value) < 5:
        return jsonify({"error": "Phrase must be at least 5 characters"}), 400

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    cred = get_credential(credential_id)
    if not cred or cred["user_id"] != user["id"]:
        return jsonify({"error": "Invalid credential"}), 401

    if not verify_recovery(user["id"], current_value):
        return jsonify({"error": "Current recovery value is incorrect"}), 401

    save_recovery(user["id"], new_type, new_value)
    return jsonify({"message": "Recovery method updated successfully"}), 200

@app.route("/history/<username>", methods=["GET"])
def history(username):
    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    events = get_login_history(user["id"])
    return jsonify([dict(e) for e in events])

if __name__ == "__main__":
    app.run(debug=True)
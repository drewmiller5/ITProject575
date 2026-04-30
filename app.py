from flask import Flask, request, jsonify, render_template
from database import init_db, create_user, get_user, save_credential, get_credential, get_credentials_by_user, log_login_event, get_login_history, save_security_questions, get_security_questions, verify_security_answers
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

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if len(questions_and_answers) != 3:
        return jsonify({"error": "You must set exactly 3 security questions"}), 400

    success = create_user(username)
    if not success:
        return jsonify({"error": "Username already exists"}), 409

    user = get_user(username)
    credential_id = f"cred-{username}-{user['id']}"
    save_credential(user["id"], credential_id)

    pairs = [(q["question"], q["answer"]) for q in questions_and_answers]
    save_security_questions(user["id"], pairs)

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

    # Randomize question order for challenged logins
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

    # Check each answer
    passed_answers = []
    failed_answers = []
    for a in answers:
        expected = stored.get(a["question"], "")
        from database import normalize_answer
        if normalize_answer(a["answer"]) == normalize_answer(expected):
            passed_answers.append(a)
        else:
            failed_answers.append(a)

    passed = len(passed_answers)
    total = len(answers)

    # 0 for all → immediately blocked
    if passed == 0:
        log_login_event(user["id"], ip, ua, 100, "blocked")
        return jsonify({
            "success": False,
            "blocked": True,
            "message": "Access denied — failed all questions."
        }), 401

    # All correct → let them in
    if passed == total:
        log_login_event(user["id"], ip, ua, 0, "allowed")
        return jsonify({
            "success": True,
            "message": f"Welcome {username}"
        }), 200

    # Partial correct — check escalation level
    # Build locked answers (only the ones they got correct)
    locked = [{"question": a["question"], "answer": a["answer"], "locked": True} for a in passed_answers]

    # Get questions not yet asked
    asked_questions = {a["question"] for a in answers}
    remaining = [q for q in all_questions if q["question"] not in asked_questions]

    if escalation_level < 3 and remaining:
        # Escalate — pick a random unused question
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

    # At level 3 and failed exactly one — one retry
    if escalation_level == 3 and len(failed_answers) == 1:
        return jsonify({
            "success": False,
            "retry": True,
            "escalation_level": 3,
            "message": "One question incorrect — one final attempt.",
            "previous_answers": locked,
            "retry_question": {"question": failed_answers[0]["question"], "locked": False}
        }), 200

    # Failed too many — blocked
    log_login_event(user["id"], ip, ua, 100, "blocked")
    return jsonify({
        "success": False,
        "blocked": True,
        "message": "Access denied — too many incorrect answers."
    }), 401

@app.route("/history/<username>", methods=["GET"])
def history(username):
    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    events = get_login_history(user["id"])
    return jsonify([dict(e) for e in events])

if __name__ == "__main__":
    app.run(debug=True)
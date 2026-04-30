import datetime
from database import get_db

def score_login(user_id, ip_address, user_agent):
    db = get_db()
    score = 0
    factors = []

    # 1. Time of day check
    hour = datetime.datetime.now().hour
    past_logins = db.execute(
        "SELECT timestamp FROM login_events WHERE user_id = ? ORDER BY id DESC LIMIT 20",
        (user_id,)
    ).fetchall()

    if past_logins:
        past_hours = [int(row["timestamp"][11:13]) for row in past_logins]
        avg_hour = sum(past_hours) / len(past_hours)
        deviation = abs(hour - avg_hour)
        deviation = min(deviation, 24 - deviation)
        if deviation > 6:
            score += 20
            factors.append(f"Unusual login time (hour {hour}, avg {int(avg_hour)})")
    else:
        score += 15
        factors.append("First login — no history to compare")

    # 2. New device check
    known_agents = db.execute(
        "SELECT user_agent FROM login_events WHERE user_id = ? AND outcome = 'allowed'",
        (user_id,)
    ).fetchall()
    known_agent_set = {row["user_agent"] for row in known_agents}

    if not known_agent_set:
        score += 15
        factors.append("First login — device not yet recognized")
    elif user_agent not in known_agent_set:
        score += 25
        factors.append("Unrecognized device or browser")

    # 3. New IP check
    known_ips = db.execute(
        "SELECT ip_address FROM login_events WHERE user_id = ? AND outcome = 'allowed'",
        (user_id,)
    ).fetchall()
    known_ip_set = {row["ip_address"] for row in known_ips}

    if not known_ip_set:
        score += 10
        factors.append("First login — IP not yet recognized")
    elif ip_address not in known_ip_set:
        score += 25
        factors.append(f"New IP address: {ip_address}")

    # 4. Login frequency in last 10 minutes
    recent = db.execute(
        """SELECT COUNT(*) as c FROM login_events
           WHERE user_id = ? AND timestamp >= datetime('now', '-10 minutes')""",
        (user_id,)
    ).fetchone()["c"]

    if recent >= 10:
        score += 40
        factors.append(f"Highly suspicious — {recent} logins in last 10 minutes")
    elif recent >= 5:
        score += 25
        factors.append(f"Unusual frequency — {recent} logins in last 10 minutes")
    elif recent >= 3:
        score += 10
        factors.append(f"Elevated frequency — {recent} logins in last 10 minutes")

    # 5. Recent failed challenge attempts (live counter, resets on success)
    user_row = db.execute(
        "SELECT failed_attempts FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    pending_failures = user_row["failed_attempts"] if user_row else 0

    if pending_failures >= 3:
        score += 15
        factors.append(f"Multiple recent failed challenge attempts: {pending_failures}")
    elif pending_failures >= 1:
        score += 8
        factors.append(f"Recent failed challenge attempt(s): {pending_failures}")

    # Cap at 100
    score = min(score, 100)

    # Decision thresholds
    if score <= 25:
        decision = "allowed"
    elif score <= 50:
        decision = "challenged_1"  # start with 1 question
    elif score <= 75:
        decision = "challenged_2"  # start with 2 questions
    else:
        decision = "challenged_3"  # start with 3 questions

    db.close()

    return {
        "score": score,
        "decision": decision,
        "factors": factors
    }
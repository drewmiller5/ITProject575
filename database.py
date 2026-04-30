import sqlite3
import os
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")

LOCK_THRESHOLD = 5          # failed challenge attempts before account locks
LOCK_DURATION_HOURS = 24    # hours until account auto-unlocks

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT UNIQUE NOT NULL,
            created_at       TEXT DEFAULT (datetime('now')),
            locked           INTEGER DEFAULT 0,
            failed_attempts  INTEGER DEFAULT 0,
            locked_until     TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER REFERENCES users(id),
            credential_id TEXT UNIQUE NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS login_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            timestamp   TEXT DEFAULT (datetime('now')),
            ip_address  TEXT,
            user_agent  TEXT,
            risk_score  REAL,
            outcome     TEXT
        );

        CREATE TABLE IF NOT EXISTS security_questions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER REFERENCES users(id),
            question    TEXT NOT NULL,
            answer      TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now'))
        );
        

        CREATE TABLE IF NOT EXISTS recovery (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER REFERENCES users(id),
            recovery_type TEXT NOT NULL,
            recovery_value TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
            );
            """)

        # Migrate existing databases that are missing the new columns
        existing_cols = {
            row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        migrations = {
            "locked":          "ALTER TABLE users ADD COLUMN locked INTEGER DEFAULT 0",
            "failed_attempts": "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
            "locked_until":    "ALTER TABLE users ADD COLUMN locked_until TEXT DEFAULT NULL",
        }
        for col, sql in migrations.items():
            if col not in existing_cols:
                db.execute(sql)
                print(f"Migrated: added column '{col}' to users")
        db.commit()

    print("Database initialized OK")

def create_user(username):
    with get_db() as db:
        try:
            db.execute("INSERT INTO users (username) VALUES (?)", (username,))
            db.commit()
            print(f"User {username} created")
            return True
        except sqlite3.IntegrityError:
            print(f"Username {username} already exists")
            return False

def get_user(username):
    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return user

def save_credential(user_id, credential_id):
    with get_db() as db:
        try:
            db.execute(
                "INSERT INTO credentials (user_id, credential_id) VALUES (?, ?)",
                (user_id, credential_id)
            )
            db.commit()
            print(f"Credential saved for user_id {user_id}")
            return True
        except sqlite3.IntegrityError:
            print(f"Credential already exists")
            return False

def get_credential(credential_id):
    with get_db() as db:
        cred = db.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
        return cred

def get_credentials_by_user(user_id):
    with get_db() as db:
        creds = db.execute(
            "SELECT * FROM credentials WHERE user_id = ?", (user_id,)
        ).fetchall()
        return creds

def log_login_event(user_id, ip_address, user_agent, risk_score, outcome):
    with get_db() as db:
        db.execute(
            """INSERT INTO login_events (user_id, ip_address, user_agent, risk_score, outcome)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, ip_address, user_agent, risk_score, outcome)
        )
        db.commit()
        print(f"Login event logged - outcome: {outcome}, risk: {risk_score}")

def get_login_history(user_id):
    with get_db() as db:
        events = db.execute(
            """SELECT * FROM login_events
               WHERE user_id = ?
               ORDER BY timestamp DESC LIMIT 10""",
            (user_id,)
        ).fetchall()
        return events

def save_security_questions(user_id, questions_and_answers):
    with get_db() as db:
        for question, answer in questions_and_answers:
            db.execute(
                "INSERT INTO security_questions (user_id, question, answer) VALUES (?, ?, ?)",
                (user_id, question, answer.strip().lower())
            )
        db.commit()
        print(f"Security questions saved for user_id {user_id}")

def get_security_questions(user_id):
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        return rows

def normalize_answer(answer):
    """Normalize answers so number words match digits and vice versa."""
    word_to_num = {
        'zero': '0', 'one': '1', 'two': '2', 'three': '3',
        'four': '4', 'five': '5', 'six': '6', 'seven': '7',
        'eight': '8', 'nine': '9', 'ten': '10'
    }
    num_to_word = {v: k for k, v in word_to_num.items()}
    cleaned = answer.strip().lower()
    if cleaned in word_to_num:
        return word_to_num[cleaned]
    if cleaned in num_to_word:
        return num_to_word[cleaned]
    return cleaned

def verify_security_answers(user_id, answers):
    with get_db() as db:
        rows = db.execute(
            "SELECT question, answer FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        if not rows:
            return False
        stored = {row["question"]: row["answer"] for row in rows}
        for question, answer in answers:
            stored_answer = stored.get(question, "")
            submitted = normalize_answer(answer)
            expected = normalize_answer(stored_answer)
            if submitted != expected:
                return False
        return True

# ---------------------------------------------------------------------------
# Security question management
# ---------------------------------------------------------------------------

def update_security_questions(user_id, updates):
    """Replace one or more security questions for a user.

    `updates` is a list of dicts: [{"question": "...", "answer": "..."}]
    Each entry REPLACES the existing row with the same question text, or
    inserts a new row if the question is brand new.  Questions not mentioned
    are left untouched, so partial updates (change just 1 of 3) work fine.
    Pass all 3 to do a full replacement.
    """
    with get_db() as db:
        existing = db.execute(
            "SELECT id, question FROM security_questions WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        existing_map = {row["question"]: row["id"] for row in existing}

        for item in updates:
            question = item["question"].strip()
            answer   = item["answer"].strip().lower()

            if question in existing_map:
                # Update the existing row
                db.execute(
                    "UPDATE security_questions SET question = ?, answer = ? WHERE id = ?",
                    (question, answer, existing_map[question])
                )
            else:
                # New question text — insert fresh row
                db.execute(
                    "INSERT INTO security_questions (user_id, question, answer) VALUES (?, ?, ?)",
                    (user_id, question, answer)
                )

        db.commit()
        print(f"Security questions updated for user_id {user_id} ({len(updates)} change(s))")

def delete_all_security_questions(user_id):
    """Remove all security questions for a user (used before a full recovery reset)."""
    with get_db() as db:
        db.execute(
            "DELETE FROM security_questions WHERE user_id = ?", (user_id,)
        )
        db.commit()
        print(f"All security questions deleted for user_id {user_id}")

# ---------------------------------------------------------------------------
# Lock / unlock / attempt tracking
# ---------------------------------------------------------------------------

def increment_failed_attempts(user_id):
    """Increment failed challenge attempts. Lock the account if threshold is reached."""
    with get_db() as db:
        db.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?",
            (user_id,)
        )
        db.commit()

        row = db.execute(
            "SELECT failed_attempts FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        attempts = row["failed_attempts"] if row else 0

        if attempts >= LOCK_THRESHOLD:
            lock_user(user_id)
            print(f"User {user_id} locked after {attempts} failed attempts")
            return True  # account is now locked

        print(f"User {user_id} failed attempt {attempts}/{LOCK_THRESHOLD}")
        return False  # not yet locked

def reset_failed_attempts(user_id):
    """Reset the failed attempt counter after a successful login."""
    with get_db() as db:
        db.execute(
            "UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,)
        )
        db.commit()
        print(f"Failed attempts reset for user {user_id}")

def lock_user(user_id):
    """Lock the account and set the expiry timestamp."""
    unlock_at = (
        datetime.datetime.utcnow() + datetime.timedelta(hours=LOCK_DURATION_HOURS)
    ).strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as db:
        db.execute(
            "UPDATE users SET locked = 1, locked_until = ? WHERE id = ?",
            (unlock_at, user_id)
        )
        db.commit()
        print(f"User {user_id} locked until {unlock_at}")

def auto_unlock_if_expired(user_id):
    """Check whether the lock window has passed and auto-unlock if so.
    Returns True if the account is still locked, False if it is now unlocked."""
    with get_db() as db:
        row = db.execute(
            "SELECT locked, locked_until FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        if not row or not row["locked"]:
            return False  # not locked

        if not row["locked_until"]:
            return True  # locked indefinitely (manual lock)

        locked_until = datetime.datetime.strptime(row["locked_until"], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.utcnow() >= locked_until:
            # Lock has expired — clear it
            db.execute(
                "UPDATE users SET locked = 0, locked_until = NULL, failed_attempts = 0 WHERE id = ?",
                (user_id,)
            )
            db.commit()
            print(f"User {user_id} auto-unlocked (lock window expired)")
            return False  # now unlocked

        return True  # still locked

def is_user_locked(user_id):
    """Returns True if account is currently locked (auto-unlocks if window has passed)."""
    return auto_unlock_if_expired(user_id)

def save_recovery(user_id, recovery_type, recovery_value):
    """Save a PIN or phrase for account recovery."""
    with get_db() as db:
        # Delete existing recovery first
        db.execute("DELETE FROM recovery WHERE user_id = ?", (user_id,))
        db.execute(
            "INSERT INTO recovery (user_id, recovery_type, recovery_value) VALUES (?, ?, ?)",
            (user_id, recovery_type, recovery_value.strip().lower())
        )
        db.commit()
        print(f"Recovery {recovery_type} saved for user_id {user_id}")

def get_recovery(user_id):
    """Get the recovery method for a user."""
    with get_db() as db:
        row = db.execute(
            "SELECT * FROM recovery WHERE user_id = ?", (user_id,)
        ).fetchone()
        return row

def verify_recovery(user_id, recovery_value):
    """Verify the recovery PIN or phrase."""
    with get_db() as db:
        row = db.execute(
            "SELECT recovery_value FROM recovery WHERE user_id = ?", (user_id,)
        ).fetchone()
        if not row:
            return False
        return row["recovery_value"] == recovery_value.strip().lower()

if __name__ == "__main__":
    init_db()
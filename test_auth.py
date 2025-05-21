from auth import authenticate_user

def test_missing_credentials():
    db = {}
    assert authenticate_user("", "pass", db) == "Missing credentials"
    assert authenticate_user("user", "", db) == "Missing credentials"

def test_user_not_found():
    db = {}
    assert authenticate_user("user", "pass", db) == "User not found"

def test_account_locked():
    db = {"user": {"password": "pass", "attempts": 3}}
    assert authenticate_user("user", "pass", db) == "Account locked"

def test_invalid_password():
    db = {"user": {"password": "pass", "attempts": 0}}
    assert authenticate_user("user", "wrong", db) == "Invalid password"
    assert db["user"]["attempts"] == 1

def test_success():
    db = {"user": {"password": "pass", "attempts": 1}}
    assert authenticate_user("user", "pass", db) == "Authenticated"
    assert db["user"]["attempts"] == 0



# --- Condition Combination для first if (not username or not password) ---
def test_comb_not_username_true_password_false():
    db = {"alice": {"password": "x", "attempts": 0}}
    assert authenticate_user("", "x", db) == "Missing credentials"

def test_comb_username_false_not_password_true():
    db = {"alice": {"password": "x", "attempts": 0}}
    assert authenticate_user("alice", "", db) == "Missing credentials"

def test_comb_both_true():
    db = {}
    assert authenticate_user("", "", db) == "Missing credentials"

def test_comb_both_false():
    db = {"bob": {"password": "pwd", "attempts": 0}}
    result = authenticate_user("bob", "pwd", db)
    assert result == "Authenticated"

# --- MC/DC: незалежна перевірка кожного аргументу in (not username or not password) ---
def test_mcdc_username_alone_triggers():
    db = {}
    assert authenticate_user("", "anything", db) == "Missing credentials"

def test_mcdc_password_alone_triggers():
    db = {}
    assert authenticate_user("someone", "", db) == "Missing credentials"

def test_mcdc_both_nonempty_suppresses():
    db = {"u": {"password": "p", "attempts": 0}}
    assert authenticate_user("u", "p", db) == "Authenticated"

# --- Path Coverage: шлях attempts 2→wrong→attempts=3→locked ---
def test_path_two_failures_then_lock():
    db = {"user": {"password": "secret", "attempts": 2}}
    assert authenticate_user("user", "bad", db) == "Invalid password"
    assert db["user"]["attempts"] == 3
    assert authenticate_user("user", "secret", db) == "Account locked"

# --- Data Flow Testing: перевірка default attempts та їх перезапису ---
def test_data_flow_default_attempts_and_reset():
    db = {"new": {"password": "pw"}} 
    assert authenticate_user("new", "wrong", db) == "Invalid password"
    assert db["new"]["attempts"] == 1
    assert authenticate_user("new", "pw", db) == "Authenticated"
    assert db["new"]["attempts"] == 0
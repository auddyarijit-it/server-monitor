from fastapi import FastAPI, Request, Header, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
import pymysql
import secrets
from datetime import datetime, timezone, timedelta
import html

from utils.emailer import send_server_alert

import uuid
from utils.emailer import send_password_reset_email

from calendar import monthrange
from datetime import datetime

app = FastAPI(title="Server Monitor API")

# -----------------------------
# Rate Limiting (SAFE ADDITION)
# -----------------------------
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.responses import JSONResponse

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."}
    )
# -----------------------------
# Database Config
# -----------------------------
DB_CONFIG = {
    "host": "localhost",
    "user": "servermonitor",
    "password": "servermonitor",
    "database": "server_monitor",
    "cursorclass": pymysql.cursors.DictCursor
}

def get_db():
    return pymysql.connect(**DB_CONFIG)
# -----------------------------
# API KEY VERIFICATION (AGENT AUTH)
# -----------------------------
from fastapi import Header

def verify_api_key(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing API key")

    api_key = authorization.split(" ")[1]

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id, server_name FROM servers WHERE api_key=%s",
        (api_key,)
    )
    server = cur.fetchone()

    cur.close()
    conn.close()

    if not server:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return server

# -----------------------------
# JWT Config
# -----------------------------
SECRET_KEY = "CHANGE_THIS_TO_RANDOM_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=60))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- FIX 1: Retrieve full user data including role from DB ---
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id, email, role FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user # Returns a dictionary with 'role'
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -----------------------------
# ALERT CONFIG
# -----------------------------
CPU_THRESHOLD = 80
RAM_THRESHOLD = 80
DISK_THRESHOLD = 90
CONSECUTIVE_CHECKS = 3

# -----------------------------
# Health Check
# -----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -----------------------------
# Login
# -----------------------------
@app.post("/v1/login")
@limiter.limit("5/minute")
def login(request: Request, data: dict):
    email = data.get("email")
    password = data.get("password")

    connection = get_db()
    cursor = connection.cursor()

    # --- FIX 2: Ensure password_hash is the correct column name ---
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={
            "sub": user["email"],
            "role": user["role"]  # <--- THIS IS THE FIX
             },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}

# --- User Management API ---

# --- FIX 3: Correct Dependency Logic ---
def check_admin_role(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "Admin":
        raise HTTPException(status_code=403, detail="Only Admins can manage users")
    return current_user

@app.get("/v1/admin/users") # Changed path to match your other v1 patterns
def list_users(admin=Depends(check_admin_role)):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id, email, role, created_at FROM users")
    users = cursor.fetchall()
    cursor.close()
    connection.close()
    return users

@app.post("/v1/admin/add-user")
def add_user(data: dict, admin=Depends(check_admin_role)):
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "viewer") 
    
    if not email or not password:
        raise HTTPException(status_code=400, detail="Missing data")
        
    hashed_password = pwd_context.hash(password)
    
    connection = get_db()
    cursor = connection.cursor()
    try:
        # --- FIX 4: Column name matching (password_hash) ---
        cursor.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
            (email, hashed_password, role)
        )
        connection.commit()
    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        cursor.close()
        connection.close()
    return {"message": "User created successfully"}

@app.delete("/v1/admin/delete-user/{user_id}")
def delete_user(user_id: int, admin=Depends(check_admin_role)):
    connection = get_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    connection.commit()
    cursor.close()
    connection.close()
    return {"message": "User deleted"}

# -----------------------------
# Receive Metrics (Agent)
# -----------------------------
@app.post("/v1/metrics")
@limiter.limit("60/minute")   # ? rate limit per IP
async def receive_metrics(
    request: Request,
    server: dict = Depends(verify_api_key)  # ?? API-key enforced here
):
    """
    Receives metrics from agent using API key authentication.
    """

    data = await request.json()

    # Server is already verified by verify_api_key()
    server_id = server["id"]

    connection = get_db()
    cursor = connection.cursor()

    # -----------------------------
    # Disk extraction (SAFE)
    # -----------------------------
    disk_percent = None
    if data.get("disk"):
        first_disk = next(iter(data["disk"].values()), None)
        if first_disk:
            disk_percent = first_disk.get("percent")
    # -----------------------------
    # Insert Metrics
    # -----------------------------
    cursor.execute("""
        INSERT INTO metrics
        (server_id, cpu_usage, ram_used_mb, ram_total_mb, ram_percent,
         disk_used_percent, uptime_seconds, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        server_id,
        data.get("cpu_usage"),
        data.get("ram", {}).get("used_mb"),
        data.get("ram", {}).get("total_mb"),
        data.get("ram", {}).get("percent"),
        disk_percent,
        data.get("uptime_seconds"),
        datetime.now(timezone.utc)
    ))

    cursor.execute(
        "UPDATE servers SET last_seen=%s WHERE id=%s",
        (datetime.now(timezone.utc), server_id)
    )

    # -----------------------------
    # ALERT CHECK
    # -----------------------------
    cursor.execute("""
        SELECT cpu_usage, ram_percent, disk_used_percent
        FROM metrics
        WHERE server_id=%s
        ORDER BY created_at DESC
        LIMIT %s
    """, (server_id, CONSECUTIVE_CHECKS))

    last_metrics = cursor.fetchall()

    if len(last_metrics) == CONSECUTIVE_CHECKS:

        cpu_alert = all(
            m["cpu_usage"] is not None and m["cpu_usage"] > CPU_THRESHOLD
            for m in last_metrics
        )

        ram_alert = all(
            m["ram_percent"] is not None and m["ram_percent"] > RAM_THRESHOLD
            for m in last_metrics
        )

        disk_alert = all(
            m["disk_used_percent"] is not None and m["disk_used_percent"] > DISK_THRESHOLD
            for m in last_metrics
        )

        def create_alert(alert_type, message):
            message = html.escape(message)

            cursor.execute("""
                SELECT *
                FROM alerts
                WHERE server_id=%s AND alert_type=%s AND is_active=TRUE
                LIMIT 1
            """, (server_id, alert_type))

            existing = cursor.fetchone()

            # FIRST ALERT
            if not existing:
                cursor.execute("""
                    INSERT INTO alerts
                    (server_id, alert_type, message,
                     notification_count, last_notified_at, is_active)
                    VALUES (%s,%s,%s,1,%s,TRUE)
                """, (
                    server_id,
                    alert_type,
                    message,
                    datetime.now(timezone.utc)
                ))

                cursor.execute(
                    "SELECT server_name FROM servers WHERE id=%s",
                    (server_id,)
                )
                server_name = cursor.fetchone()["server_name"]

                send_server_alert(server_name, alert_type, message)

            # REMINDER ALERT
            else:
                new_count = existing["notification_count"] + 1

                cursor.execute("""
                    UPDATE alerts
                    SET notification_count=%s,
                        last_notified_at=%s
                    WHERE id=%s
                """, (
                    new_count,
                    datetime.now(timezone.utc),
                    existing["id"]
                ))

                if new_count % CONSECUTIVE_CHECKS == 0:
                    cursor.execute(
                        "SELECT server_name FROM servers WHERE id=%s",
                        (server_id,)
                    )
                    server_name = cursor.fetchone()["server_name"]

                    send_server_alert(
                        server_name,
                        alert_type,
                        f"{alert_type} usage above threshold for 3 consecutive checks"
                    )

        # KEEP OLD LOGIC (UNCHANGED)
        if cpu_alert:
            create_alert("CPU", "CPU usage above 80% for 3 consecutive checks")

        if ram_alert:
            create_alert("RAM", "RAM usage above 80% for 3 consecutive checks")

        if disk_alert:
            create_alert("DISK", "Disk usage above 90% for 3 consecutive checks")

        # AUTO RESOLVE
        def resolve_alert(alert_type, is_alert):
            if not is_alert:
                cursor.execute("""
                    UPDATE alerts
                    SET is_active=FALSE, resolved_at=%s
                    WHERE server_id=%s AND alert_type=%s AND is_active=TRUE
                """, (datetime.now(timezone.utc), server_id, alert_type))

        resolve_alert("CPU", cpu_alert)
        resolve_alert("RAM", ram_alert)
        resolve_alert("DISK", disk_alert)

    connection.commit()
    cursor.close()
    connection.close()

    return {"status": "success"}

# -----------------------------
# Add Server
# -----------------------------
@app.post("/v1/admin/add-server")
def add_server(data: dict, user: dict = Depends(get_current_user)):

    connection = get_db()
    cursor = connection.cursor()

    server_name = data.get("server_name")
    project = data.get("project")
    environment = data.get("environment")

    if not server_name:
        raise HTTPException(status_code=400, detail="Server name required")

    api_key = secrets.token_hex(32)

    cursor.execute("""
        INSERT INTO servers (server_name, api_key, project, environment)
        VALUES (%s, %s, %s, %s)
    """, (server_name, api_key, project, environment))

    connection.commit()
    cursor.close()
    connection.close()

    return {
        "status": "success",
        "server_name": server_name,
        "api_key": api_key
    }

# -----------------------------
# Delete Server
# -----------------------------
@app.delete("/v1/admin/delete-server/{server_id}")
def delete_server(server_id: int, user: dict = Depends(get_current_user)):

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM servers WHERE id=%s", (server_id,))
    connection.commit()

    cursor.close()
    connection.close()

    return {"status": "deleted"}


# -----------------------------
# Dashboard (ENHANCED – NON-BREAKING)
# -----------------------------
@app.get("/v1/servers")
def get_servers(user: dict = Depends(get_current_user)):


    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            s.id,
            s.server_name,
            s.project,
            s.environment,
            s.last_seen,

            m.cpu_usage,
            m.ram_percent,
            m.disk_used_percent,
            m.created_at,

            -- Alert info
            COUNT(a.id) AS active_alerts_count,
            MAX(CASE WHEN a.is_active = TRUE THEN 1 ELSE 0 END) AS has_active_alert,
            GROUP_CONCAT(DISTINCT a.alert_type) AS alert_types

        FROM servers s

        LEFT JOIN metrics m ON m.id = (
            SELECT id FROM metrics
            WHERE server_id = s.id
            ORDER BY created_at DESC
            LIMIT 1
        )

        LEFT JOIN alerts a
            ON a.server_id = s.id
           AND a.is_active = TRUE

        GROUP BY s.id

        ORDER BY
            has_active_alert DESC,        -- ?? Problem servers first
            m.created_at DESC             -- Latest activity next
    """)

    servers = cursor.fetchall()
    cursor.close()
    connection.close()

    return servers
# -----------------------------
# Forgot Password
# -----------------------------
@app.post("/v1/forgot-password")
@limiter.limit("3/minute")
def forgot_password(request: Request, data: dict):
    email = data.get("email")

    if not email:
        raise HTTPException(status_code=400, detail="Email required")

    conn = get_db()
    cur = conn.cursor()

    # Find user
    cur.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    if user:
        token = str(uuid.uuid4())
        expiry = datetime.now(timezone.utc) + timedelta(minutes=30)

        # ? Insert into password_resets table
        cur.execute("""
            INSERT INTO password_resets (user_id, token, expires_at, used)
            VALUES (%s, %s, %s, 0)
        """, (user["id"], token, expiry))

        conn.commit()

        reset_link = f"https://servermonitor.tsdemo.co.in/reset.html?token={token}"
        send_password_reset_email(email, reset_link)

    cur.close()
    conn.close()

    # Always return success (security)
    return {"status": "If email exists, reset link sent"}
# -----------------------------
# Reset Password
# -----------------------------
@app.post("/v1/reset-password")
def reset_password(data: dict):
    token = data.get("token")
    new_password = data.get("password")

    if not token or not new_password:
        raise HTTPException(status_code=400, detail="Invalid request")

    conn = get_db()
    cur = conn.cursor()

    # ? Validate token
    cur.execute("""
        SELECT pr.id, pr.user_id
        FROM password_resets pr
        WHERE pr.token=%s
          AND pr.used=0
          AND pr.expires_at > %s
    """, (token, datetime.now(timezone.utc)))

    reset = cur.fetchone()

    if not reset:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    hashed = pwd_context.hash(new_password)

    # ? Update password
    cur.execute("""
        UPDATE users
        SET password_hash=%s
        WHERE id=%s
    """, (hashed, reset["user_id"]))

    # ? Mark token as used
    cur.execute("""
        UPDATE password_resets
        SET used=1
        WHERE id=%s
    """, (reset["id"],))

    conn.commit()
    cur.close()
    conn.close()

    return {"status": "Password reset successful"}
# -----------------------------
# Monthly Reports (CPU / RAM / DISK)
# -----------------------------
@app.get("/v1/reports/monthly")
def monthly_report(
    server_id: int,
    month: str,  # YYYY-MM
    user: dict = Depends(get_current_user)
):
    """
    Returns per-day AVG CPU/RAM/DISK usage for a server for a given month
    """

    try:
        year, mon = map(int, month.split("-"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid month format")

    start_date = datetime(year, mon, 1, tzinfo=timezone.utc)
    end_day = monthrange(year, mon)[1]
    end_date = datetime(year, mon, end_day, 23, 59, 59, tzinfo=timezone.utc)

    conn = get_db()
    cur = conn.cursor()

    # ?? Aggregate per day
    cur.execute("""
        SELECT
            DATE(created_at) AS day,
            ROUND(AVG(cpu_usage), 2) AS cpu,
            ROUND(AVG(ram_percent), 2) AS ram,
            ROUND(AVG(disk_used_percent), 2) AS disk
        FROM metrics
        WHERE server_id = %s
          AND created_at BETWEEN %s AND %s
        GROUP BY DATE(created_at)
        ORDER BY DATE(created_at)
    """, (server_id, start_date, end_date))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    # ?? Format exactly how frontend expects
    result = []
    for r in rows:
        result.append({
            "day": r["day"].strftime("%d"),
            "cpu": r["cpu"] or 0,
            "ram": r["ram"] or 0,
            "disk": r["disk"] or 0
        })

    return result
# -----------------------------
# Monthly Reports (Analytics)
# -----------------------------
@app.get("/v1/reports/analytics")
def analytics_report(
    server_id: int,
    start_date: str,
    end_date: str,
    stat_type: str = "AVG",
    user: dict = Depends(get_current_user)
):
    """
    Advanced analytics for date range
    stat_type: AVG | MAX | MIN
    server_id = 0 => all servers combined
    """

    if stat_type not in ("AVG", "MAX", "MIN"):
        raise HTTPException(status_code=400, detail="Invalid stat_type")

    try:
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
    except:
        raise HTTPException(status_code=400, detail="Invalid date format")

    agg = stat_type  # SQL-safe because validated

    conn = get_db()
    cur = conn.cursor()

    if server_id == 0:
        # ?? All servers combined
        query = f"""
            SELECT
                DATE(created_at) AS day,
                ROUND({agg}(cpu_usage), 2) AS cpu,
                ROUND({agg}(ram_percent), 2) AS ram,
                ROUND({agg}(disk_used_percent), 2) AS disk
            FROM metrics
            WHERE created_at BETWEEN %s AND %s
            GROUP BY DATE(created_at)
            ORDER BY day
        """
        cur.execute(query, (start, end))
    else:
        # Single server
        query = f"""
            SELECT
                DATE(created_at) AS day,
                ROUND({agg}(cpu_usage), 2) AS cpu,
                ROUND({agg}(ram_percent), 2) AS ram,
                ROUND({agg}(disk_used_percent), 2) AS disk
            FROM metrics
            WHERE server_id = %s
              AND created_at BETWEEN %s AND %s
            GROUP BY DATE(created_at)
            ORDER BY day
        """
        cur.execute(query, (server_id, start, end))

    rows = cur.fetchall()
    cur.close()
    conn.close()

    return rows
# -----------------------------
# Admin: Alert History
# -----------------------------
@app.get("/v1/admin/alerts")
def get_alert_history(admin: dict = Depends(check_admin_role)):

    connection = get_db()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            a.id,
            s.server_name,
            a.alert_type,
            a.message,
            a.notification_count,
            a.is_active,
            a.created_at,
            a.last_notified_at,
            a.resolved_at
        FROM alerts a
        JOIN servers s ON s.id = a.server_id
        ORDER BY a.created_at DESC
        LIMIT 200
    """)

    alerts = cursor.fetchall()

    cursor.close()
    connection.close()

    return alerts
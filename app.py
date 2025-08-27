from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import psycopg2
import bcrypt
from flask_session import Session
import os
import urllib.parse as up

app = Flask(__name__)


DATABASE_URL = os.getenv("postgresql://fintrackdb_gvp5_user:EhrUZmSPh85bOg6W0kcboxo0ErxwTVVr@dpg-d2nilpgdl3ps73cpgchg-a/fintrackdb_gvp5")

# Flask session config
app.secret_key = "mytemporarysecretkey"
  # Secure random secret key
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database config
if DATABASE_URL:
    up.uses_netloc.append("postgres")
    url = up.urlparse(DATABASE_URL)

    DB_CONFIG = {
        "dbname": url.path[1:],
        "user": url.username,
        "password": url.password,
        "host": url.hostname,
        "port": url.port,
    }
else:
    # Fallback for local dev
    DB_CONFIG = {
        "dbname": "fintrackdb",
        "user": "postgres",
        "password": "Parv@2005",
        "host": "localhost",
        "port": "5432"
    }

# Admin password in plain text for easy control (Change for production)
ADMIN_PASSWORD_PLAIN = "adminpass"

# Hash admin password once
ADMIN_HASHED_PASSWORD = bcrypt.hashpw(ADMIN_PASSWORD_PLAIN.encode('utf-8'), bcrypt.gensalt())

# Database helper
def execute_query(query, params=None, fetch=True):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute(query, params if params else ())
        data = cursor.fetchall() if fetch else None
        conn.commit()
        cursor.close()
        conn.close()
        return data
    except Exception as e:
        print(f"Database error: {e}")
        raise Exception(f"Database error: {str(e)}")

# Home
@app.route("/")
def index():
    return render_template("index.html")

# User Login Page
@app.route("/user-login", methods=["GET"])
def user_login():
    return render_template("user-login.html")

# User Login API
@app.route("/api/user/login", methods=["POST"])
def api_user_login():
    data = request.get_json()
    email = data.get("email")
    try:
        user_id = int(data.get("user_id"))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid User ID format"}), 400

    if not email or not user_id:
        return jsonify({"error": "Email and User ID required"}), 400

    try:
        query = "SELECT user_id FROM users WHERE email = %s AND user_id = %s"
        user = execute_query(query, (email, user_id))
        if not user:
            return jsonify({"error": "Invalid email or user ID"}), 401

        session["user_id"] = user_id
        return jsonify({"message": "Login successful", "user_id": user_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Dashboard (user)
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("user_login"))
    return render_template("dashboard.html")

# Admin Login Page
@app.route("/admin-login")
def admin_login():
    return render_template("admin-login.html")

# Admin Login API
@app.route("/api/admin/login", methods=["POST"])
def admin_login_api():
    data = request.get_json()
    password = data.get("password")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    password_bytes = password.encode('utf-8')

    if bcrypt.checkpw(password_bytes, ADMIN_HASHED_PASSWORD):
        session["admin"] = True
        return jsonify({"message": "Admin login successful"}), 200
    else:
        return jsonify({"error": "Invalid admin password"}), 401

# Admin Dashboard
@app.route("/admin-dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    return render_template("admin-dashboard.html")

# Advisor Dashboard
@app.route("/advisor-dashboard")
def advisor_dashboard():
    if "user_id" not in session:
        return redirect(url_for("user_login"))
    return render_template("advisor-dashboard.html")

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Advisor Request API
@app.route("/api/advisor-request", methods=["POST"])
def advisor_request():
    data = request.get_json()
    user_id = data.get('userId')
    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400

    request_advisor = data.get('requestAdvisor')

    if not user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400

    try:
        if request_advisor:
            # Fetch an available advisor (e.g., with the fewest users assigned)
            advisor_query = """
                SELECT advisor_id 
                FROM advisors 
                ORDER BY (
                    SELECT COUNT(*) 
                    FROM users 
                    WHERE users.advisor_id = advisors.advisor_id
                ) ASC 
                LIMIT 1
            """
            result = execute_query(advisor_query)
            if not result:
                return jsonify({'success': False, 'message': 'No advisors available'}), 500

            selected_advisor_id = result[0][0]

            # Assign the advisor
            query = """
                UPDATE users 
                SET advisor_requested = TRUE, advisor_id = %s 
                WHERE user_id = %s
            """
            execute_query(query, (selected_advisor_id, user_id), fetch=False)
        else:
            query = """
                UPDATE users 
                SET advisor_requested = FALSE, advisor_id = NULL 
                WHERE user_id = %s
            """
            execute_query(query, (user_id,), fetch=False)

        return jsonify({'success': True, 'advisor_assigned': request_advisor}), 200

    except Exception as e:
        print(f"Error processing advisor request: {e}")
        return jsonify({'success': False, 'message': 'Could not process request.'}), 500

# @app.route('/advisor_req')
# def new_advisor():
#     return render_template('new_advisor.html')
# @app.route('/user-dashboard-info/<int:user_id>')
# def user_dashboard_info(user_id):
#     # Sample dummy data for now
#     portfolios = [
#         {"portfolio_id": 1, "portfolio_name": "Growth Fund"},
#         {"portfolio_id": 2, "portfolio_name": "Retirement Plan"}
#     ]
#     return {"portfolios": portfolios}

@app.route('/advisor_req')
def investments_and_returns():
    user_id = session.get('user_id')
    # Fetch investments and total returns data
    investments_data = fetch_user_investments(user_id)
    total_returns_data = fetch_total_returns(user_id)
    
    return render_template('new_advisor.html', investments=investments_data, total_returns=total_returns_data)

def fetch_user_investments(user_id):
    # Logic to fetch user investments from the database or API
    pass

def fetch_total_returns(user_id):
    # Logic to fetch total returns from the database or API
    pass


# User Portfolios
@app.route("/user-portfolios/<int:user_id>")
def get_user_portfolios(user_id):
    try:
        query = "SELECT portfolio_id, portfolio_name FROM Portfolio WHERE user_id = %s"
        portfolios = execute_query(query, (user_id,))
        return jsonify([{"portfolio_id": p[0], "portfolio_name": p[1]} for p in portfolios]) if portfolios else jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Goals
@app.route("/user-goals/<int:user_id>")
def get_user_goals(user_id):
    try:
        query = "SELECT goal_id, goal_name FROM Goal WHERE user_id = %s"
        goals = execute_query(query, (user_id,))
        return jsonify([{"goal_id": g[0], "goal_name": g[1]} for g in goals]) if goals else jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Investments
@app.route("/user-investments/<int:user_id>")
def get_user_investments(user_id):
    try:
        query = """
            SELECT i.investment_id, i.security_name, i.amount_invested, i.current_value
            FROM Investment i
            JOIN Portfolio p ON i.portfolio_id = p.portfolio_id
            WHERE p.user_id = %s
        """
        investments = execute_query(query, (user_id,))
        return jsonify([
            {"investment_id": inv[0], "security_name": inv[1], "amount_invested": inv[2], "current_value": inv[3]}
            for inv in investments
        ]) if investments else jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Portfolio Investments
@app.route("/portfolio-investments/<int:portfolio_id>")
def get_portfolio_investments(portfolio_id):
    try:
        query = "SELECT investment_id, security_name FROM Investment WHERE portfolio_id = %s"
        investments = execute_query(query, (portfolio_id,))
        return jsonify([
            {"investment_id": inv[0], "security_name": inv[1]}
            for inv in investments
        ]) if investments else jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Admin User Summary
@app.route("/admin/user-summary/<int:user_id>")
def get_user_summary(user_id):
    try:
        query = "SELECT get_user_summary(%s)"
        result = execute_query(query, (user_id,))
        return jsonify(result[0][0])  # because result is [[jsonb]]
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Portfolio Value
@app.route("/portfolio-value/<int:portfolio_id>")
def get_portfolio_value(portfolio_id):
    try:
        query = "SELECT * from GetPortfolioValue(%s)"
        result = execute_query(query, (portfolio_id,))
        print(result[0][0])
        return jsonify({"portfolio_value": float(result[0][0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Goal Status
@app.route("/goal-status/<int:goal_id>")
def is_goal_met(goal_id):
    try:
        query = "SELECT IsGoalMet(%s)"
        result = execute_query(query, (goal_id,))
        return jsonify({"goal_met": result[0][0]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Investment Performance
@app.route("/investment-performance/<int:investment_id>")
def get_investment_performance(investment_id):
    try:
        query = "SELECT GetInvestmentPerformance(%s)"
        result = execute_query(query, (investment_id,))
        return jsonify({"investment_performance": float(result[0][0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Total Returns
@app.route("/total-returns/<int:user_id>")
def get_total_user_returns(user_id):
    try:
        query = "SELECT GetTotalUserReturns(%s)"
        result = execute_query(query, (user_id,))
        return jsonify({"total_returns": float(result[0][0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Active Investments
@app.route("/active-investments/<int:user_id>")
def count_active_investments(user_id):
    try:
        query = """
            SELECT COUNT(DISTINCT i.investment_id)
            FROM Investment i
            JOIN Portfolio p ON i.portfolio_id = p.portfolio_id
            WHERE p.user_id = %s
        """
        result = execute_query(query, (user_id,))
        return jsonify({"active_investments": float(result[0][0])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Run app
if __name__ == "__main__":
    app.run(debug=True, port=3000)
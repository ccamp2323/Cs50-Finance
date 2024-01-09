import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
now = datetime.now()
dt_string = now.strftime("%d/%m/%Y %H:%M:%S")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stock_info = db.execute("SELECT symbol, shares FROM own WHERE user_id=?", session["user_id"])
    stock_summary = []
    total_portfolio_value = 0

    for stock in stock_info:
        shares = stock["shares"]
        if shares > 0:
            symbol = stock["symbol"]
            symbol_price = lookup(symbol)
            symbol_price = symbol_price["price"]
            total_price = symbol_price*shares
            stock_summary.append({
                "symbol": symbol,
                "shares": shares,
                "symbol_price": symbol_price,
                "total_price": total_price
            })
            total_portfolio_value += total_price
    cash = db.execute("SELECT cash from users WHERE id=? ", session["user_id"])
    total_cash = None
    if cash:
        cash = cash[0]["cash"]
        total_cash = total_portfolio_value+cash
    return render_template("index.html", stock_summary=stock_summary, total_cash=total_cash, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    symbol_buy = request.form.get("symbol")
    shares = request.form.get("shares")
    if request.method == "POST":
        if not symbol_buy or not shares:
            return apology("must provide symbol and shares", 400)
        elif not shares.isdigit() or int(shares) <= 0 or int(shares) != round(int(shares)):
            return apology("Invalid number of shares", 400)
        stock = lookup(symbol_buy)
        if not stock:
            return apology("Invalid symbol", 400)
        cash = db.execute("SELECT cash from users WHERE id=? ", session["user_id"])
        cash = cash[0]["cash"]
        price = stock["price"]*int(shares)
        if cash >= price:
            remain = cash-price
            db.execute("INSERT INTO purchase (user_id,symbol,symbol_price,shares,total_price,time) VALUES(?,?,?,?,?,?)",
                       session["user_id"], stock["symbol"], stock["price"], shares, price, dt_string)
            db.execute("UPDATE users SET cash=? WHERE id= ?", remain, session["user_id"])
            own = db.execute("SELECT symbol,shares FROM own where symbol=? AND user_id=?", stock["symbol"], session["user_id"])
            if not own:
                db.execute("INSERT INTO own (user_id,symbol,shares) VALUES(?,?,?)", session["user_id"], stock["symbol"], shares)
            else:
                new_shares = (own[0]["shares"])+int(shares)
                db.execute("UPDATE own SET shares=? WHERE symbol=? AND user_id=?", new_shares, stock["symbol"], session["user_id"])
        else:
            return apology("You don't have enough money", 400)

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    bought = db.execute("SELECT * FROM purchase WHERE user_id=?", session["user_id"])
    sold = db.execute("SELECT * FROM sells WHERE user_id=?", session["user_id"])
    return render_template("history.html", bought=bought, sold=sold)


@app.route("/setting", methods=["GET", "POST"])
@login_required
def setting():
    current = request.form.get("current_pass")
    new = request.form.get("new_pass")
    if request.method == "POST":
        if not current or not new:
            return apology("You should provide current and new password", 403)
        row = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])
        if row and check_password_hash(row[0]["hash"], current):
            db.execute("UPDATE users SET hash=? WHERE id=?", generate_password_hash(new), session["user_id"])
            return redirect("/")
        else:
            return apology("Incorrect password", 403)
    return render_template("setting.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    symbol = request.form.get("symbol")
    if request.method == "POST":
        if not symbol:
            return apology("must provide symbol", 400)
        quote = lookup(symbol)
        if not quote:
            return apology("invalid symbol", 400)
        return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if not request.form.get("username"):
            return apology("must provide username", 400)
        if db.execute("SELECT * FROM users WHERE username = ?", username):
            return apology("username is already exsist", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not confirmation:
            return apology("must confirm password", 400)

        # Query database for username
        if password == confirmation:
            rows = db.execute(
                "INSERT INTO users (username,hash) VALUES (?,?)", username, generate_password_hash(password)
            )
            return redirect("/")
        else:
            return apology("Retype the same password", 400)

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stock_info = db.execute("SELECT symbol,shares FROM own WHERE user_id=? GROUP BY symbol", session["user_id"])
    stocks = []
    for stock in stock_info:
        symbol = stock["symbol"]
        if stock["shares"] > 0:
            stocks.append(symbol)
    shares = request.form.get("shares")
    symbol = request.form.get("symbol")
    own_shares = db.execute("SELECT shares FROM own WHERE user_id=? AND symbol=? GROUP BY symbol", session["user_id"], symbol)
    if request.method == "POST":
        if not symbol or not shares:
            return apology("You should select symbol and number of shares", 400)
        if not shares.isdigit() or int(shares) <= 0 or int(shares) > own_shares[0]["shares"] or int(shares) != round(int(shares)):
            return apology("Invalid number of shares", 400)
        if symbol not in stocks:
            return apology("Invalid symbol", 400)
        stock = lookup(symbol)
        price = stock["price"]*int(shares)
        db.execute("INSERT INTO sells (user_id,symbol,shares,symbol_price,total_price,time) VALUES(?,?,?,?,?,?)",
                   session["user_id"], stock["symbol"], int(shares), stock["price"], price, dt_string)
        db.execute("UPDATE own SET shares=? WHERE symbol=? AND user_id=?",
                   (own_shares[0]["shares"]-int(shares)), symbol, session["user_id"])
        cash = db.execute("SELECT cash from users WHERE id=? ", session["user_id"])
        cash = cash[0]["cash"]
        remain = cash+price
        db.execute("UPDATE users SET cash=? WHERE id= ?", remain, session["user_id"])

        return redirect("/")

    return render_template("sell.html", stocks=stocks)

import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from datetime import datetime
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Display data about all the values of stock that the users hold
    refresh_index(session["user_id"])

    portfolios = db.execute("SELECT * FROM portfolio WHERE id = ?", session["user_id"])
    holdings = db.execute("SELECT SUM(total) FROM portfolio WHERE id = ?", session["user_id"])[0]["SUM(total)"]
    cash = round(db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"], 2)
    if holdings != None:
        total = round(cash + holdings, 2)
    else:
        total = cash

    return render_template("index.html", portfolios=portfolios, cash=usd(cash), total=usd(total), func=usd)
    return apology("Page failed to load", 404)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        if not request.form.get("shares"):
            return apology("must buy at least one share", 400)
        if request.form.get("shares").isalpha() == True or float(request.form.get("shares")) < 0 or float(request.form.get("shares")).is_integer() != True:
            return apology("your answer cannot include negative numbers or fractional quantities", 400)

        # Check if symbol exists
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))
        if lookup(symbol) != None:
            # Define necessary variables for calculations
            stock = lookup(symbol)
            stock_name = stock["name"]
            stock_price = stock["price"]
            session_id = session["user_id"]
            savings = db.execute("SELECT cash FROM users WHERE id = ?", session_id)[0]["cash"]
            total_price = shares * stock_price

            # Check if the amount user purchases can be afforded
            if savings < total_price:
                return apology("You do not have enough money in your savings")
            else:
                # Add to user history
                db.execute("INSERT INTO history (id, symbol, shares, company, transaction_amount, type, time) VALUES (?, ?, ?, ?, ?,"
                           "?, ?)", session_id, symbol, shares, stock_name, stock_price, "Buy", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                # Update cash in users tables
                new_savings = savings - total_price
                db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_price, session_id)

                # Update portfolio

                # Check if its a first time entry
                first_time = db.execute("SELECT * FROM portfolio WHERE name = ? and id = ?", stock_name, session_id)

                # If first time
                if len(first_time) == 0:
                    db.execute("INSERT INTO portfolio (id, name, shares, symbol) VALUES (?, ?, ?, ?)",
                               session_id, stock_name, shares, symbol)
                # If already entered
                else:
                    db.execute("UPDATE portfolio SET shares = shares + ? WHERE id = ? AND name = ?", shares, session_id, stock_name)
        else:
            return apology("Invalid Symbol", 400)

        # UPDATE THE INDEX BEFORE RELOADING

        # Select symbols from portfolio and run lookup function on them for current prices
        refresh_index(session_id)
        return redirect("/")

    else:
        return render_template("buy.html")

    return apology("Page failed to load", 404)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE id = ?", session["user_id"])
    # return str(history)
    return render_template("history.html", history=history)

    return apology("Failed to load page", 404)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    if request.method == "POST":
        # Check if symbol entered
        if not request.form.get("symbol"):
            return apology("must provide symbol", 400)
        # Check if symbol exists
        symbol = request.form.get("symbol").upper()
        if lookup(symbol) != None:
            stock = lookup(symbol)
            stock_name = stock["name"]
            stock_price = usd(round(stock["price"], 2))

            # Show Quoted page
            return render_template("quoted.html", symbol=symbol, stock_name=stock_name, stock_price=stock_price)
        else:
            return apology("Invalid Symbol", 400)
    else:
        return render_template("quote.html")
    return apology("Failed to load page", 404)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    db = SQL("sqlite:///finance.db")
    # when request is get, it should display registration
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)
        if "'" in request.form.get("username") or ";" in request.form.get("username"):
            return apology("username cannot contain apostrophes or semicolons", 403)

        # check if username is already used
        username = request.form.get("username")
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(rows) > 0:
            return apology("must provide unique username", 400)
        password = request.form.get("password")

        # hash password
        password_hash = generate_password_hash(request.form.get("password"))

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
        return redirect("/login")

    # check for invalid entries i.e. passwords that don't match when enetered twice
    # and if username is already in use

    else:
        return render_template("register.html")

    return apology("Failed to load page", 404)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        # Pass checks
        if not request.form.get("shares"):
            return apology("must sell at least one share", 400)
        if request.form.get("stock") == "Stocks:":
            return apology("must provide symbol", 400)
        if request.form.get("shares").isalpha() == True or float(request.form.get("shares")) < 0 or float(request.form.get("shares")).is_integer() != True:
            return apology("your answer cannot include negative numbers or fractional quantities", 400)

        # Define variables from forms
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        session_id = session["user_id"]

        # Check if the user is selling too many shares
        shares_held = db.execute("SELECT shares FROM portfolio WHERE id = ? AND symbol = ?", session_id, symbol)[0]["shares"]
        if shares > shares_held:
            return apology("You can't sell more shares than you own")

        # Define variables
        stock = lookup(symbol)
        stock_name = stock["name"]
        stock_price = stock["price"]

        savings = db.execute("SELECT cash FROM users WHERE id = ?", session_id)[0]["cash"]
        total_price = shares * stock_price

        # Add sell to user history
        db.execute("INSERT INTO history (id, symbol, shares, company, transaction_amount, type, time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   session_id, symbol, shares, stock_name, stock_price, "Sell", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Update cash in users tables
        new_savings = savings + total_price
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_price, session_id)

        # Update portfolio
        db.execute("UPDATE portfolio SET shares = shares - ? WHERE id = ? AND name = ?", shares, session_id, stock_name)

        # Update the index
        refresh_index(session_id)
        return redirect("/")

    else:
        stock_options = []
        symbols = db.execute("SELECT symbol FROM portfolio WHERE id = ?", session["user_id"])
        for i in range(len(symbols)):
            stock_options.append(symbols[i]["symbol"])
        length = len(stock_options)

        return render_template("sell.html", stocks=stock_options, length=length)


@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        if not request.form.get("amount"):
            return apology("must add at least 1 dollar", 400)
        deposit = request.form.get("amount")
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", float(deposit), session["user_id"])
        return redirect("/")

    else:
        return render_template("deposit.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


def refresh_index(session_id):
    symbols = db.execute("SELECT symbol, shares FROM portfolio WHERE id = ?", session_id)

    stock_prices = []
    stock_shares = []

    for i in range(len(symbols)):
        stock_prices.append(lookup(symbols[i]["symbol"])["price"])
        stock_shares.append(symbols[i]["shares"])

    stock_totals = [a * b for a, b in zip(stock_prices, stock_shares)]
    cash = sum(stock_totals)

    for i in range(len(stock_prices)):
        db.execute("UPDATE portfolio SET price = ? WHERE symbol = ?", stock_prices[i], symbols[i]["symbol"])
        db.execute("UPDATE portfolio SET total = ? WHERE symbol = ?", round(stock_totals[i], 2), symbols[i]["symbol"])
    check_empty = db.execute("SELECT * FROM portfolio WHERE id = ?", session_id)
    for i in range(len(check_empty)):
        if check_empty[i]["shares"] == 0:
            db.execute("DELETE FROM portfolio WHERE name = ? ", check_empty[i]["name"])

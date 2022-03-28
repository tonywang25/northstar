import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///northstar.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()

    if request.method == "GET":
        return render_template("register.html")

    else:
        # checks for username
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # checks for password
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # checks for confirmation
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        # checks for password and confirmation
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password does not match confirmation", 400)

        # checks for confirmation
        elif not request.form.get("northstar"):
            return apology("must provide north star", 400)

        # checks for special characters in password
        special_chars = ["$", "&", "!", "."]
        sc_counter = 0
        password = request.form.get("password")
        for char in password:
            if char in special_chars:
                sc_counter += 1
        if sc_counter == 0:
            return apology("Invalid password. Must include at least one special character, such as $, &, !, .")

        # checks for unique usernames in database
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username already taken", 400)

        username = request.form.get("username")

        # creates password hash
        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # requests "northstar" from html and stores it into a variable
        northstar = request.form.get("northstar")

        # inserts username, pass hash, and northstar into the users table in the northstar database
        db.execute("INSERT INTO users (username, hash, northstar) values (?, ?, ?)", username, hash, northstar)
        user_id = db.execute("SELECT id FROM users WHERE username = ?", username)


        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # keeps user logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/setup")


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "GET":
        return render_template("setup.html")
    else:
        user_id = session["user_id"]
        current_ns = db.execute("SELECT northstar FROM users WHERE id = ?", user_id)

        # checks for valid input
        if not request.form.get("c_star"):
            return apology("Must provide a constellation goal", 400)
        if not request.form.get("category"):
            return apology("Must provide a category", 400)
        if not request.form.get("c_star_2"):
            return apology("Must provide a second constellation goal", 400)
        if not request.form.get("category_2"):
            return apology("Must provide a second category", 400)
        if not request.form.get("c_star_3"):
            return apology("Must provide a third constellation goal", 400)
        if not request.form.get("category_3"):
            return apology("Must provide a third category", 400)

        # requests "constellation star" and "category" from html template and stores it into a variable
        c_star = request.form.get("c_star")
        category = request.form.get("category")
        c_star_2 = request.form.get("c_star_2")
        category_2 = request.form.get("category_2")
        c_star_3 = request.form.get("c_star_3")
        category_3 = request.form.get("category_3")

        # stores the constellation star and tag into the tags table
        db.execute("INSERT INTO categories (category_name, user_id, c_star) values (?, ?, ?)", category, user_id, c_star)
        db.execute("INSERT INTO categories (category_name, user_id, c_star) values (?, ?, ?)", category_2, user_id, c_star_2)
        db.execute("INSERT INTO categories (category_name, user_id, c_star) values (?, ?, ?)", category_3, user_id, c_star_3)
        # FIGURE OUT HOW TO LOOP THIS PART
        return redirect("/")


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


@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    # POST
    if request.method == "POST":
        user_id = session["user_id"]
        user_categories = db.execute("SELECT * FROM categories WHERE user_id = ?", user_id)

        # checks for valid inputs
        if not request.form.get("task"):
            return apology("must input a task", 403)
        if not request.form.get("category") or request.form.get("category") == "Category":
            return apology("must select a category", 403)

        # stores post requests in category_name and task
        category_name = request.form.get("category")
        task = request.form.get("task")

        # stores into database
        category_id = db.execute("SELECT id FROM categories WHERE category_name = ? AND user_id = ?", category_name, user_id)
        db.execute("INSERT INTO tasks (category_id, task, user_id) VALUES (?,?,?)", category_id[0]["id"], task, user_id)
        task_ids = db.execute("SELECT id FROM tasks WHERE user_id = ?", user_id)

        # Tried to implement dynamic deletion funcitonality by using a for loop to check over the requests of all the task_ids that the 'Delete' buttons use.
        # for id in task_ids:
        #     if request.form.get(id):
        #         db.execute("DELETE FROM tasks WHERE id = ?", id)

        return redirect("/")

    # GET
    else:
        user_id = session["user_id"]
        current_user = db.execute("SELECT username, northstar FROM users WHERE id = ?", user_id)
        user_categories = db.execute("SELECT * FROM categories WHERE user_id = ?", user_id)
        for category in user_categories:
            category["tasks"] = db.execute("SELECT * FROM tasks WHERE category_id = ? AND user_id = ?", category["id"], user_id)
        return render_template("dashboard.html", current_user=current_user, user_categories=user_categories)


@app.route("/constellation", methods=["GET", "POST"])
@login_required
def constellation():
    # POST
    if request.method == "POST":
        user_id = session["user_id"]
        current_user = db.execute("SELECT username, northstar FROM users WHERE id = ?", user_id)
        
        if not request.form.get("c_star"):
            return apology("Must provide a constellation goal", 400)
        if not request.form.get("category"):
            return apology("Must provide a category", 400)

        c_star = request.form.get("c_star")
        category = request.form.get("category")
        db.execute("INSERT INTO categories (category_name, user_id, c_star) values (?, ?, ?)", category, user_id, c_star)
        return redirect("/constellation")

    # GET
    else:
        user_id = session["user_id"]
        current_user = db.execute("SELECT username, northstar FROM users WHERE id = ?", user_id)
        user_categories = db.execute("SELECT * FROM categories WHERE user_id = ?", user_id)
        return render_template("constellation.html", current_user=current_user, user_categories=user_categories)


@app.route("/task_view", methods=["GET", "POST"])
@login_required
def task_view():
    # POST
    if request.method == "POST":
        # Tried to implement dynamic deletion funcitonality by using a for loop to check over the requests of all the task_ids that the 'Delete' buttons use.
        # user_id = session["user_id"]
        # tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", user_id)
        # for id in tasks[0]["id"]:
        #     if request.form.get(id):
        #         db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", id, user_id)
        return redirect("/task_view")
    # GET
    else:
        user_id = session["user_id"]
        current_user = db.execute("SELECT username, northstar FROM users WHERE id = ?", user_id)
        user_tasks = db.execute("SELECT * FROM tasks JOIN categories ON tasks.category_id = categories.id WHERE categories.user_id = ?", user_id)
        return render_template("/task_view.html", user_id=user_id, current_user=current_user, user_tasks=user_tasks)


@app.route("/category_removal", methods=["GET", "POST"])
@login_required
def category_removal():
    # POST
    if request.method == "POST":
        user_id = session["user_id"]

        if not request.form.get("category") or request.form.get("category") == "Category":
            return apology("must select a category to remove", 403)

        category_name = request.form.get("category")
        category_id = db.execute("SELECT id FROM categories WHERE category_name = ? AND user_id = ?", category_name, user_id)

        db.execute("DELETE FROM categories WHERE id = ? and user_id = ?", category_id[0]["id"], user_id)
        db.execute("DELETE FROM tasks WHERE category_id = ? and user_id = ?", category_id[0]["id"], user_id)

        return redirect("/category_removal")
    # GET
    else:
        user_id = session["user_id"]
        user_categories = db.execute("SELECT * FROM categories WHERE user_id = ?", user_id)
        return render_template("/category_removal.html",user_categories=user_categories)

@app.route("/task_removal", methods=["GET", "POST"])
@login_required
def task_removal():
    # POST
    if request.method == "POST":
        user_id = session["user_id"]
        if not request.form.get("task") or request.form.get("task") == "Task":
            return apology("must select a task to remove", 403)
        
        task = request.form.get("task")
        
        db.execute("DELETE FROM tasks WHERE task = ? and user_id = ?", task, user_id)
        return redirect("/task_removal")
    # GET
    else:
        user_id = session["user_id"]
        user_tasks = db.execute("SELECT * FROM tasks WHERE user_id = ?", user_id)
        return render_template("/task_removal.html", user_tasks=user_tasks)

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

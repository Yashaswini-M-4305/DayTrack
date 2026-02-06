from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
from collections import defaultdict
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.config['DEBUG'] = True

# 🔥 CRITICAL: Force NEW database file (Render cache bypass)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///journal_fresh.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_change_this_in_production'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_gmail_app_password'

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    monthly_budget = db.Column(db.Float, default=0)

class MonthlyBudget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    month = db.Column(db.String(7), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'month', 'year', name='unique_budget_per_user_month'),)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100))
    amount = db.Column(db.Float)
    date = db.Column(db.Date)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class VisitedPlace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    review = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class FoodTried(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    review = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class WatchedShow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    review = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 🔥 ULTIMATE RENDER FIX: Delete ALL old DB files + create FRESH database
with app.app_context():
    # Delete ALL possible old database files
    for db_file in ['journal.db', 'journal_fresh.db']:
        if os.path.exists(db_file):
            os.remove(db_file)
            print(f"🗑️ DELETED: {db_file}")
    
    # Create PERFECTLY FRESH database with ALL columns
    db.create_all()
    print("✅ FRESH DATABASE CREATED - ALL COLUMNS EXIST!")

# ✅ PUBLIC LANDING PAGE (NO login_required)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DayTracker</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <body class="bg-light">
        <div class="container mt-5 text-center">
            <h1 class="display-4 mb-4">📊 DayTracker</h1>
            <p class="lead mb-5">Track your expenses, experiences & more!</p>
            <a href="/login" class="btn btn-primary btn-lg me-3">Login</a>
            <a href="/register" class="btn btn-outline-primary btn-lg">Register</a>
        </div>
    </body>
    </html>
    '''

@app.route('/home')
@login_required
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 5
    
    today = datetime.date.today()
    first_day = datetime.date(today.year, today.month, 1)
    next_month_first_day = (
        datetime.date(today.year + 1, 1, 1)
        if today.month == 12
        else datetime.date(today.year, today.month + 1, 1)
    )

    expenses_query = Expense.query.filter(
        Expense.user_id == current_user.id,
        Expense.date >= first_day,
        Expense.date < next_month_first_day
    )
    
    pagination = expenses_query.paginate(page=page, per_page=per_page, error_out=False)
    expenses_for_chart = expenses_query.all()

    daily_spending = defaultdict(float)
    for expense in expenses_for_chart:
        day_str = expense.date.strftime("%Y-%m-%d")
        daily_spending[day_str] += expense.amount

    chart_labels = sorted(daily_spending.keys())
    chart_data = [daily_spending[date] for date in chart_labels]
    
    total_spent = sum(expense.amount for expense in pagination.items) if pagination.items else 0
    budget = current_user.monthly_budget or 0
    remaining_budget = max(0, budget - total_spent)

    return render_template(
        'home.html',
        expenses=pagination.items,
        pagination=pagination,
        total_spent=total_spent,
        remaining_budget=remaining_budget,
        budget=budget,
        chart_labels=chart_labels,
        chart_data=chart_data
    )

@app.route('/set_budget', methods=['GET', 'POST'])
@login_required
def set_budget():
    if request.method == 'POST':
        amount = float(request.form['budget'])
        month = request.form['month']
        year = int(request.form['year'])
        
        existing = MonthlyBudget.query.filter_by(
            user_id=current_user.id, 
            month=month, 
            year=year
        ).first()
        if existing:
            db.session.delete(existing)
        
        new_budget = MonthlyBudget(
            user_id=current_user.id,
            amount=amount,
            month=month,
            year=year
        )
        db.session.add(new_budget)
        db.session.commit()
        flash('Monthly budget updated!')
        return redirect(url_for('home'))
    
    return render_template('set_budget.html')

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    description = request.form['description']
    amount = float(request.form['amount'])
    date = datetime.datetime.strptime(request.form['date'], '%Y-%m-%d').date()
    new_expense = Expense(description=description, amount=amount, date=date, user_id=current_user.id)
    db.session.add(new_expense)
    db.session.commit()
    flash('Expense added successfully!')
    return redirect(url_for('home'))

@app.route('/delete_expense/<int:id>', methods=['POST'])
@login_required
def delete_expense(id):
    expense = Expense.query.get_or_404(id)
    if expense.user_id != current_user.id:
        flash('Unauthorized attempt to delete expense!')
        return redirect(url_for('home'))
    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted!')
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Registration successful!')
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('home'))
        flash('Wrong username or password!')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out!')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_reset_token(user.email, app.config['SECRET_KEY'])
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)
            flash('Check your email for the password reset link.')
        else:
            flash('No user found with that email.')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token, app.config['SECRET_KEY'])
    if not email:
        flash('Reset link expired or invalid.')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        new_password = request.form['new_password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Your password has been updated. Please log in.')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/experiences')
@login_required
def experiences():
    places = VisitedPlace.query.filter_by(user_id=current_user.id).all()
    foods = FoodTried.query.filter_by(user_id=current_user.id).all()
    shows = WatchedShow.query.filter_by(user_id=current_user.id).all()
    return render_template('experiences.html', places=places, foods=foods, shows=shows)

@app.route('/add_visited_place', methods=['POST'])
@login_required
def add_visited_place():
    name = request.form['name']
    review = request.form.get('review', "")
    new_place = VisitedPlace(name=name, review=review, user_id=current_user.id)
    db.session.add(new_place)
    db.session.commit()
    flash('Visited place added!')
    return redirect(url_for('experiences'))

@app.route('/add_food_tried', methods=['POST'])
@login_required
def add_food_tried():
    name = request.form['name']
    review = request.form.get('review', "")
    new_food = FoodTried(name=name,

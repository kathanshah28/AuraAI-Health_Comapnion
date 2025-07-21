import os
import json
import re # Import the regular expression module
import google.generativeai as genai
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- App Initialization and Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Gemini API Configuration ---
try:
    # It's more secure to set this as an environment variable
    # In your terminal: export GEMINI_API_KEY_NEW='YOUR_API_KEY'
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY_NEW"))
    model = genai.GenerativeModel('models/gemini-1.5-flash-latest')
except (KeyError, TypeError):
    print("🚨 FATAL ERROR: GEMINI_API_KEY_NEW environment variable not set.")
    print("The application cannot run without a Gemini API key.")
    exit()


# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    onboarded = db.Column(db.Boolean, default=False)
    profile_data = db.Column(db.Text, nullable=True)

class NutritionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    calories = db.Column(db.Integer, default=0)
    protein = db.Column(db.Integer, default=0)
    carbs = db.Column(db.Integer, default=0)
    fat = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref=db.backref('nutrition_logs', lazy=True))

# New model to store individual meal entries
class MealLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    description = db.Column(db.String(300), nullable=False)
    calories = db.Column(db.Integer, default=0)
    protein = db.Column(db.Integer, default=0)
    carbs = db.Column(db.Integer, default=0)
    fat = db.Column(db.Integer, default=0)
    user = db.relationship('User', backref=db.backref('meal_logs', lazy=True))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Gemini Helper Functions ---
def extract_json_from_string(text):
    """
    Finds and extracts the first valid JSON object from a string.
    """
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return match.group(0)
    return None

def get_nutritional_blueprint(profile):
    """Generates the nutritional plan using the Gemini API."""
    prompt = f"""
    Based on the following user profile, create a detailed "Daily Nutritional Blueprint".
    User Profile: {json.dumps(profile, indent=2)}
    Your task:
    1. Calculate an estimated Total Daily Energy Expenditure (TDEE) in calories.
    2. Based on the user's goals, determine a target daily calorie intake.
    3. Break down the target calories into macronutrient targets: Protein (g), Carbohydrates (g), and Fats (g).
    4. Provide a brief, one-paragraph summary of the plan.
    Present the output as a JSON object with keys: "target_calories", "target_protein", "target_carbs", "target_fat", and "summary".
    Example: {{"target_calories": 2000, "target_protein": 150, "target_carbs": 200, "target_fat": 60, "summary": "Your plan focuses on..."}}
    """
    try:
        response = model.generate_content(prompt)
        json_string = extract_json_from_string(response.text)
        if json_string:
            return json.loads(json_string)
        else:
            print(f"Error: No JSON object found in blueprint response: {response.text}")
            return {"error": "Could not parse blueprint from AI response."}
    except Exception as e:
        print(f"Error generating blueprint: {e}")
        return {"error": "Could not generate blueprint."}

def analyze_meal_with_gemini(meal_description, blueprint):
    """Analyzes a meal and provides suggestions using Gemini."""
    prompt = f"""
    A user's daily nutritional blueprint is: {json.dumps(blueprint, indent=2)}
    The user just ate: "{meal_description}"
    Your tasks:
    1.  Estimate the macronutrients (protein, carbs, fat) and calories for THIS meal.
    2.  Provide actionable advice for their next meal.
    3.  Suggest a healthy fruit or snack.
    Return a JSON object with keys: "meal_estimate" (containing "calories", "protein", "carbs", "fat"), "next_meal_suggestion", and "snack_suggestion".
    Example: {{"meal_estimate": {{"calories": 400, "protein": 30, "carbs": 50, "fat": 10}}, "next_meal_suggestion": "For dinner...", "snack_suggestion": "An apple..."}}
    """
    try:
        response = model.generate_content(prompt)
        json_string = extract_json_from_string(response.text)
        if json_string:
            return json.loads(json_string)
        else:
            print(f"Error: No JSON object found in meal analysis response: {response.text}")
            return {"error": "Could not parse meal analysis from AI response."}
    except Exception as e:
        print(f"Error analyzing meal: {e}")
        return {"error": "Could not analyze meal."}


# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Registration successful! Please complete your profile.', 'success')
        return redirect(url_for('onboarding'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            if user.onboarded:
                return redirect(url_for('dashboard'))
            else:
                flash('Please complete your profile before proceeding.', 'info')
                return redirect(url_for('onboarding'))
        else:
            flash('Login failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/onboarding', methods=['GET', 'POST'])
@login_required
def onboarding():
    if current_user.onboarded:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        profile_data = {
            "age": request.form['age'],
            "gender": request.form['gender'],
            "weight": request.form['weight'],
            "height": request.form['height'],
            "activity_level": request.form['activity_level'],
            "health_goals": request.form['health_goals'],
            "conditions": request.form['conditions'],
            "diet_prefs": request.form['diet_prefs']
        }
        
        blueprint = get_nutritional_blueprint(profile_data)
        if "error" in blueprint:
            flash('Could not generate your nutritional blueprint. Please try again.', 'danger')
            return render_template('onboarding.html')

        profile_data['nutritional_blueprint'] = blueprint
        
        current_user.profile_data = json.dumps(profile_data)
        current_user.onboarded = True
        db.session.commit()
        
        flash('Profile created successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('onboarding.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.onboarded:
        return redirect(url_for('onboarding'))
    
    profile = json.loads(current_user.profile_data)
    blueprint = profile.get('nutritional_blueprint', {})
    
    blueprint_is_valid = True
    if not isinstance(blueprint, dict):
        blueprint_is_valid = False
    else:
        required_keys = ['target_calories', 'target_protein', 'target_carbs', 'target_fat']
        for key in required_keys:
            if not (key in blueprint and isinstance(blueprint.get(key), (int, float)) and blueprint.get(key) > 0):
                blueprint_is_valid = False
                break

    if not blueprint_is_valid:
        flash('Your wellness profile is incomplete. Please complete the onboarding process again.', 'danger')
        current_user.onboarded = False
        db.session.commit()
        return redirect(url_for('onboarding'))

    today = datetime.utcnow().date()
    # Get total nutrition for the day
    todays_log = NutritionLog.query.filter_by(user_id=current_user.id, date=today).first()
    if not todays_log:
        todays_log = NutritionLog(user_id=current_user.id)
    
    # Get individual meals for the day
    todays_meals = MealLog.query.filter_by(user_id=current_user.id, date=today).order_by(MealLog.id.desc()).all()
    
    return render_template('dashboard.html', user=current_user, blueprint=blueprint, todays_log=todays_log, todays_meals=todays_meals)

@app.route('/log_meal', methods=['POST'])
@login_required
def log_meal():
    meal_description = request.form['meal_description']
    if not meal_description:
        flash('Please describe your meal.', 'warning')
        return redirect(url_for('dashboard'))

    profile = json.loads(current_user.profile_data)
    blueprint = profile.get('nutritional_blueprint', {})

    analysis = analyze_meal_with_gemini(meal_description, blueprint)

    if "error" not in analysis and 'meal_estimate' in analysis:
        meal_estimate = analysis.get('meal_estimate', {})
        today = datetime.utcnow().date()

        # Create a log for the individual meal
        new_meal = MealLog(
            user_id=current_user.id,
            date=today,
            description=meal_description,
            calories=meal_estimate.get('calories', 0),
            protein=meal_estimate.get('protein', 0),
            carbs=meal_estimate.get('carbs', 0),
            fat=meal_estimate.get('fat', 0)
        )
        db.session.add(new_meal)

        # Update the daily aggregate log
        todays_log = NutritionLog.query.filter_by(user_id=current_user.id, date=today).first()
        if not todays_log:
            todays_log = NutritionLog(user_id=current_user.id, date=today)
            db.session.add(todays_log)
        
        current_calories = todays_log.calories or 0
        current_protein = todays_log.protein or 0
        current_carbs = todays_log.carbs or 0
        current_fat = todays_log.fat or 0

        todays_log.calories = current_calories + meal_estimate.get('calories', 0)
        todays_log.protein = current_protein + meal_estimate.get('protein', 0)
        todays_log.carbs = current_carbs + meal_estimate.get('carbs', 0)
        todays_log.fat = current_fat + meal_estimate.get('fat', 0)
        
        db.session.commit()
    elif "error" in analysis:
        flash(f"AI Error: {analysis['error']}", "danger")

    session['last_analysis'] = analysis
    return redirect(url_for('dashboard'))

@app.route('/wellness_check', methods=['POST'])
@login_required
def wellness_check():
    user_feeling = request.form['user_feeling']
    
    crisis_keywords = ['kill myself', 'suicide', 'self-harm', 'hopeless', 'want to die']
    if any(keyword in user_feeling.lower() for keyword in crisis_keywords):
        response_text = "IMPORTANT: It sounds like you are going through a very difficult time. Please consider reaching out to a professional immediately. You can connect with people who can support you by calling or texting 988 anytime in the US and Canada. In India, you can call the Kiran helpline at 1800-599-0019. Please, reach out for help."
    else:
        prompt = f"""
        A user is doing a mental wellness check-in and has shared: "{user_feeling}"
        Your Role: Act as a compassionate, non-judgmental AI companion.
        1. Acknowledge and validate their feeling.
        2. Do NOT give medical advice.
        3. Suggest a simple, actionable mindfulness technique (e.g., breathing exercise, gratitude prompt).
        Keep the tone gentle and supportive.
        """
        try:
            response = model.generate_content(prompt)
            response_text = response.text
        except Exception as e:
            response_text = f"Sorry, I couldn't process that. Error: {e}"

    session['wellness_response'] = response_text
    return redirect(url_for('dashboard'))

@app.route('/progress')
@login_required
def progress():
    return render_template('progress.html', user=current_user)

@app.route('/api/nutrition_data')
@login_required
def nutrition_data():
    logs = NutritionLog.query.filter_by(user_id=current_user.id).order_by(NutritionLog.date.asc()).limit(30).all()
    
    profile = json.loads(current_user.profile_data)
    blueprint = profile.get('nutritional_blueprint', {})
    
    data = {
        "labels": [log.date.strftime('%b %d') for log in logs],
        "datasets": [
            {
                "label": "Calories Consumed",
                "data": [log.calories for log in logs],
                "borderColor": "#36A2EB",
                "backgroundColor": "rgba(54, 162, 235, 0.5)",
                "fill": False,
                "yAxisID": "y"
            },
            {
                "label": "Protein (g)",
                "data": [log.protein for log in logs],
                "borderColor": "#4BC0C0",
                "backgroundColor": "rgba(75, 192, 192, 0.5)",
                "fill": False,
                "yAxisID": "y1"
            },
            {
                "label": "Carbs (g)",
                "data": [log.carbs for log in logs],
                "borderColor": "#FFCE56",
                "backgroundColor": "rgba(255, 206, 86, 0.5)",
                "fill": False,
                "yAxisID": "y1"
            },
            {
                "label": "Fat (g)",
                "data": [log.fat for log in logs],
                "borderColor": "#FF6384",
                "backgroundColor": "rgba(255, 99, 132, 0.5)",
                "fill": False,
                "yAxisID": "y1"
            }
        ],
        "targets": {
            "calories": blueprint.get('target_calories'),
            "protein": blueprint.get('target_protein'),
            "carbs": blueprint.get('target_carbs'),
            "fat": blueprint.get('target_fat')
        }
    }
    return jsonify(data)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
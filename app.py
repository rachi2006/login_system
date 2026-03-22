
from flask import Flask, render_template, request, redirect, session, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import os
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("secret_key")

# 🔗 MongoDB Atlas (replace with your URL)
client = MongoClient(os.getenv("MONGO_URI"))  
db = client["login_system"]
users = db["users"]
roadmaps = db["roadmaps"]

# 🔐 Token generator
serializer = URLSafeTimedSerializer(app.secret_key)

# ------------------ LOGIN ------------------
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']   # username OR email
        password = request.form['password']

        # find user by email OR username
        user = users.find_one({
            "$or": [
                {"email": login_input},
                {"username": login_input}
            ]
        })

        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            wellcome = f"👋 Welcome, {user['username']}! You are now logged in."
            return f"<h1>{wellcome}</h1>"

        return "❌ Invalid credentials"

    return render_template('login.html')

# ------------------ REGISTER ------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        # check if user exists
        if users.find_one({"$or": [{"email": email}, {"username": username}]}):
            return "⚠️ Username or Email already exists"

        users.insert_one({
            "username": username,
            "email": email,
            "password": password
        })

        return redirect('/login')

    return render_template('register.html')

# ------------------ FORGOT PASSWORD ------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']

        if not users.find_one({"email": email}):
            return "❌ Email not found"

        token = serializer.dumps(email, salt='reset-password')
        reset_link = url_for('reset', token=token, _external=True)

        print("\n🔗 RESET LINK (copy in browser):", reset_link)

        return "📩 Reset link printed in terminal"

    return render_template('forgot.html')

# ------------------ RESET PASSWORD ------------------
@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=300)
    except:
        return "❌ Link expired"

    if request.method == 'POST':
        new_password = generate_password_hash(request.form['password'])
        users.update_one({"email": email}, {"$set": {"password": new_password}})
        return redirect('/login')

    return render_template('reset.html')


# ------------------ LOGOUT ------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# ------------------
if __name__ == "__main__":
    app.run(debug=True)
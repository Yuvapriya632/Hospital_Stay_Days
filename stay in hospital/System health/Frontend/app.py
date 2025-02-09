from flask import Flask, render_template, request, redirect, url_for, flash, session
import joblib
import os
import pandas as pd
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Set a secret key for session management
app.secret_key = 'your_secret_key'

# Simulating a user database (replace with a real database in production)
users_db = {}
feature_names = ['City_Code_Hospital','Hospital_code','Available Extra Rooms in Hospital','Visitors with Patient','Admission_Deposit']
# Load the pre-trained model
with open('model.pkl', 'rb') as file:
    loaded_model = joblib.load(file)

@app.route('/')
def Home():
    return render_template('Home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users_db:
            return "User already exists, please log in."
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        # Store user info in the simulated database
        users_db[username] = hashed_password
        
        return redirect(url_for('login'))
    
    return render_template('signup.html')
    


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username not in users_db:
            return "User does not exist. Please sign up first."
        
        # Check password hash
        if not check_password_hash(users_db[username], password):
            return "Incorrect password. Try again."
        
        # Store the username in session after successful login
        session['username'] = username
        
        return redirect(url_for('predict'))
    
    return render_template('login.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'username' not in session:
        return redirect(url_for('Home'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        # Retrieve user input from the form
        city_code_hospital = float(request.form['City_Code_Hospital'])
        hospital_code = float(request.form['Hospital_code'])
        extra_rooms = float(request.form['Available_Extra_Rooms_in_Hospital'])
        visitors_with_patient = float(request.form['Visitors_with_Patient'])
        admission_deposit = float(request.form['Admission_Deposit'])

        # Prepare the input data for the model
        user_input = [[city_code_hospital, hospital_code, extra_rooms, visitors_with_patient, admission_deposit]]
        input_df = pd.DataFrame(user_input, columns=['City_Code_Hospital', 'Hospital_code', 'Available Extra Rooms in Hospital', 'Visitors with Patient', 'Admission_Deposit'])
        
        # Make predictions
        prediction = loaded_model.predict(input_df)
        print(prediction[0])

        # Show the result page with the prediction
        return render_template('result.html', prediction=prediction[0])

    return render_template('predict.html')


@app.route('/logout')
def logout():
    session.pop('username', None)  # Clear session data
    flash("You have logged out successfully.", "success")
    return redirect(url_for('Home'))

if __name__ == '__main__':
    app.run(debug=True)

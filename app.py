from flask import Flask, request, session
from flask_mysqldb import MySQL
from passlib.hash import pbkdf2_sha256
import MySQLdb.cursors
import yaml
import re
import secret

app = Flask(__name__)
app.secret_key = secret.config_values.get("flask_secret_key")

# Parse yaml file
with open('db.yaml', 'r') as file:
    db = yaml.safe_load(file)

# Configure db
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']

mysql = MySQL(app)

# register new account


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if (request.method == 'POST' and 'username' in request.form
        and 'password' in request.form and 'email' in request.form
            and 'address' in request.form and 'phone_number' in request.form):
        # Store all the values from the request
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        address = request.form['address']
        phone_number = request.form['phone_number']

        # encrypt the user password for security purposes
        hashed_password = pbkdf2_sha256.hash(password)

        # check existence of account
        # reminder to separate username and email verification
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM users WHERE email = % s OR username = % s', (email, username))
        account = cursor.fetchone()

        # Validations for the account details
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'name must contain only characters and numbers !'
        else:
            cursor.execute("INSERT INTO users(username,password,email,phone_number,address) VALUES(%s, %s, %s, %s, %s)",
                           [username, hashed_password, email, phone_number, address])
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return msg


@app.route('/login', methods=['POST'])
def login():
    msg = ''
    if (request.method == 'POST' and 'username' in request.form
       and 'password' in request.form):
        # Store the values from the form
        username = request.form['username']
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM users WHERE username = % s', (username, ))
        account = cursor.fetchone()

        if account:
            if pbkdf2_sha256.verify(password, account.get("password")):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                msg = 'Logged in successfully !'
                return msg
            else:
                msg = 'Invalid password!'
                return msg
        else:
            msg = 'The account does not exist! Please check your username.'
            return msg


if __name__ == '__main__':
    app.run(debug=True)

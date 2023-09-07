from flask import Flask, request, session
from flask_mysqldb import MySQL
from passlib.hash import pbkdf2_sha256
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, get_jwt, jwt_required
from flask_cors import CORS
import MySQLdb.cursors
import yaml
import re
import secret

app = Flask(__name__)
app.secret_key = secret.config_values["flask_secret_key"]

# Parse yaml file
with open('db.yaml', 'r') as file:
    db = yaml.safe_load(file)

# Configure db
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']

app.config['JWT_SECRET_KEY'] = secret.config_values["jwt_secret_key"]
jwt = JWTManager(app)
mysql = MySQL(app)
CORS(app)

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
    response = {}
    if (request.method == 'POST' and 'username' in request.json
       and 'password' in request.json):
        # Store the values from the form
        username = request.json['username']
        password = request.json['password']
       
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM users WHERE username = % s', (username, ))
        account = cursor.fetchone()

        if account:
            if pbkdf2_sha256.verify(password, account.get("password")):
                # create an access token for the user
                access_token = create_access_token(identity=account["id"])
                session['loggedin'] = True
                session['username'] = account['username']
                msg = 'Logged in successfully !'
                response['msg'] = msg
                response['status'] = 200
                return response
            else:
                msg = 'Invalid password!'
                response['msg'] = msg
                response['status'] = 401
                return response
        else:
            msg = 'The account does not exist! Please check your username.'
            response['msg'] = msg
            response['status'] = 401
            return response


if __name__ == '__main__':
    app.run(debug=True)


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    token = request.headers.get('Authorization').split()[1]
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        'INSERT INTO blacklisted_tokens(token) VALUES(%s)',
        [token]
    )
    mysql.connection.commit()
    msg = 'Successfully logged out!'
    return msg

'''
Genglin Yu
SDEV 300
20220709.py
This is the program that will display all the state detailed information as a table.
But user need to register and login before go to the redirecting page.
pass will saved as passLib. All state details will read through csv file.
The url redirection is now working properly. But there could be some better method
to accomplish the same goal.
The new feature that added to this program is:
Change Password page that can change a user's password
A logger that will log all the failure attempt on login, with ip and time
A commonPassword sequence textfile that will deny a common sequence password
'''  # Intro
import re
import socket
import logging
from passlib.hash import sha256_crypt
from flask import Flask, render_template, request, flash
import pandas

app = Flask(__name__)

'''global value stored'''
PASSLIB = []


@app.route('/')
def index():
    """Index page"""
    return render_template("lab7_pwd.html")


@app.route('/UserRegistrationForm', methods=['POST'])
def success_register():
    """check if successfully registered"""
    input_new_psw = request.form['name']
    input_psw = request.form['psw']
    hash_pass = sha256_crypt.hash(input_psw)
    pass_one = input_new_psw + "," + hash_pass
    try:
        # check common sequence in CommonPassword file
        with open('CommonPassword.txt', "r", encoding="ascii") as file:
            common_sequence = file.readlines()
            for common in common_sequence:
                common = common.split('\n')[0]  # remove nextline
                # check lowercase matches a string pattern in passfile
                if re.findall(common, input_psw.lower()):
                    return render_template('lab7_register.html',
                                           repeat='Please do not use common pattern for password!')
        # read repeat password
        with open('passfile', "r", encoding="ascii") as file:
            user_profile = file.readlines()
            for dummy in user_profile:
                user_one = re.split(',', dummy)
                if user_one[0] == input_new_psw:
                    return render_template('lab7_register.html', repeat='User name already exist!')
    except FileNotFoundError:  # line will be reached only when file doesn't exist
        pass
    # append data to file
    with open('passfile', "a", encoding="ascii") as file:
        file.writelines(pass_one + '\n')
    return render_template('lab7_register.html', repeat='Done')


@app.route('/UserRegistrationForm')
def register():
    """register page"""
    return render_template("lab7_register.html")


@app.route('/login')
def login_page():
    """new page of login"""
    return render_template('lab7_login.html')


@app.route('/stateFlower', methods=['POST'])
def login_successful():
    """binary calculator page"""
    file = 'failedLogin.log'
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    pass_one = [request.form['name'], request.form['pwd']]
    with open('passfile', 'r', encoding="ascii") as file:
        for dummy in file:
            lib_one = re.split(',', dummy)

            user = lib_one[0]
            pwd = lib_one[1].strip('\n')
            if user != pass_one[0]:
                pass
            elif not sha256_crypt.verify(pass_one[1], pwd):
                pass
            else:
                try:
                    readfile = pandas.read_csv('lab3_data.csv')
                    # store row by row into the row attribute
                    state = ""
                    population = ""
                    flower = ""
                    for dummy in readfile.to_numpy():
                        state += dummy[0] + ','
                        population += str(dummy[1]) + ','
                        flower += dummy[2] + ','
                except FileNotFoundError:
                    pass
                # replace space with % (because it will not able to transfer to html)
                state = re.sub('[ ]', '%', state)
                flower = re.sub('[ ]', '%', flower)
                return render_template("lab7_state_profile.html",
                                       N=pass_one[0], S=state, P=population, F=flower)
    formatter = "%(message)s - %(asctime)s"
    logger = logging.getLogger()
    handler = logging.FileHandler('failedLogin.log')

    handler.setFormatter(logging.Formatter(formatter))
    handler.setLevel(logging.ERROR)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.critical("IP address '%s' failed attempt to login username '%s'",
                    ip_address, request.form['name'])
    return render_template("lab7_login.html", repeat='F')


@app.route('/changePassword')
def change():
    """changePassword page"""
    return render_template('lab8_changePwd.html')


@app.route("/changePassword", methods=['POST'])
def successful_change():
    """changePassword page with data transfer"""
    input_name = request.form['name']
    input_psw = request.form['psw']
    input_new_psw = request.form['new_psw']
    hash_pass = sha256_crypt.hash(input_new_psw)

    found = False
    new_profile = ""
    # read repeat password
    try:
        with open('passfile', "r", encoding="ascii") as file:
            user_profile = file.readlines()
            for dummy in user_profile:
                user_one = re.split(',', dummy)
                pwd = user_one[1].strip('\n')
                if user_one[0] != input_name:
                    new_profile += dummy
                elif not sha256_crypt.verify(input_psw, pwd):
                    new_profile += dummy
                else:
                    new_profile += dummy.replace(user_one[1], hash_pass)
                    found = True
                new_profile += '\n'
    except FileNotFoundError:
        pass

    if found:
        try:
            # check common sequence in CommonPassword file
            with open('CommonPassword.txt', "r", encoding="ascii") as file:
                common_sequence = file.readlines()
                for common in common_sequence:
                    common = common.split('\n')[0]  # remove nextline
                    # check lowercase matches a string pattern in passfile
                    if re.findall(common, input_new_psw.lower()):
                        return render_template('lab8_changePwd.html', repeat
                        ='Please do not use common pattern for password!')
        except FileNotFoundError:
            flash('CommonPassword File has not found!')
        with open('passfile', 'w', encoding="ascii") as file:
            file.truncate(0)
            file.writelines(new_profile)
        return render_template('lab8_changePwd.html', repeat='Done')
    return render_template('lab8_changePwd.html',
                           repeat='Username or password is wrong')


if __name__ == '__main__':
    app.run()

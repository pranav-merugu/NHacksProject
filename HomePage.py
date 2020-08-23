from flask import Flask, session, render_template, logging, redirect, url_for, flash, request
from sqlalchemy import create_engine
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy.orm import scoped_session, sessionmaker
from passlib.hash import sha256_crypt

engine = create_engine("mysql+pymysql://root:arm20out@localhost/register")

db = scoped_session(sessionmaker(bind=engine))
app = Flask(__name__, template_folder='template')
app.config["SECRET_KEY"] = "pawanhasbadhair"
socketio = SocketIO(app)


channels = {}
channels['General'] = []
channelsList = []
privateMessages = {}
usersList = {}
limit = 100

@app.route("/chat")
def index():
    return render_template('index.html')

@socketio.on('connect')
def connect():
    emit("load channels", {'channels': channels})


@socketio.on('submit to all')
def submit_to_all(data):
    message = {'text': data["mymessage"], 'username': data['username'], "time": data['time']}
    channels['General'].append(message)
    if len(channels['General']) > limit:
        channels['General'].pop(0)
    emit("announce to all", {'channels': channels}, broadcast=True)


@socketio.on('come back to general')
def come_back_to_general():
    emit("announce to all", {'channels': channels}, broadcast=True)


@socketio.on('new channel')
def new_channel(data):
    error = ""
    if data["channel"] in channelsList or data['channel'] == "General":
        error = "Channel already exist. Try again."
    elif data["channel"][0].isdigit():
        error = "Channel name cannot start with a number"
    elif ' ' in data['channel']:
        error = "Channel name can't contain space"
    else:
        channelsList.append(data['channel'])
        channels[data["channel"]] = []
    emit("add channel", {'channel': data["channel"], 'error': error})


@socketio.on('update users channels')
def update_users_channels(data):
    channel = data['channel']
    emit("update channels", {'channel': channel}, broadcast=True)


@socketio.on('join')
def join(data):
    room = data["channel"]
    join_room(room)
    message = {'text': data["mymessage"], 'username': data['username'], "time": data['time']}
    channels[data["channel"]].append(message)
    if (len(channels[data["channel"]]) > limit):
        channels[data["channel"]].pop(0)
    emit("joined", {'channels': channels}, room=room)


@socketio.on('leave')
def leave(data):
    room = data["channel"]
    leave_room(room)
    message = {'text': data["mymessage"], 'username': data['username'], "time": data['time']}
    channels[data["channel"]].append(message)
    if (len(channels[data["channel"]]) > limit):
        channels[data["channel"]].pop(0)
    emit("left", {'channels': channels}, room=room)


@socketio.on('submit to room')
def submit_to_room(data):
    room = data["channel"]
    message = {'text': data["mymessage"], 'username': data['username'], "time": data['time']}
    channels[data["channel"]].append(message)
    if (len(channels[data["channel"]]) > limit):
        channels[data["channel"]].pop(0)
    emit("announce to room", {'channels': channels}, room=room)


@socketio.on('new username')
def new_username(data):
    username = ""
    error = ""
    if data['username'] in usersList:
        error = "Username already exist. Try again"
    else:
        usersList[data['username']] = request.sid
        username = data["username"]
    emit("add username", {"username": username, 'error': error})


@socketio.on('private')
def private(data):
    message = {'text': data["mymessage"], 'username': data['username'], "time": data['time']}
    room = data['username'] + data['username2']
    if data['username'] not in privateMessages:
        privateMessages[data['username']] = {}
    if data['username2'] not in privateMessages:
        privateMessages[data['username2']] = {}
    if data['username'] not in privateMessages[data['username2']]:
        privateMessages[data['username2']][data['username']] = []
    if data['username2'] not in privateMessages[data['username']]:
        privateMessages[data['username']][data['username2']] = []
    privateMessages[data['username2']][data['username']].append(message)
    privateMessages[data['username']][data['username2']].append(message)
    if (len(privateMessages[data['username2']][data['username']]) > limit):
        privateMessages[data['username2']][data['username']].pop(0)
    if (len(privateMessages[data['username']][data['username2']]) > limit):
        privateMessages[data['username']][data['username2']].pop(0)
    socketio.server.enter_room(usersList[data['username2']], room)
    socketio.server.enter_room(request.sid, room)
    emit('private room',
         {'privateMessages': privateMessages, 'sender': data['username'], 'receiver': data['username2']}, room=room)

@app.route("/")
def home():
    return render_template('home2.html')
@app.route("/register", methods = ['GET', 'POST'])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        secure_password = sha256_crypt.encrypt(str(password))
        if password == confirm:
            db.execute("INSERT INTO users(name, username, password) VALUES(:name, :username, :password)",
                       {"name":name, "username":username, "password":secure_password})
            db.commit()
            flash("You are registered and can log in", "success")
            return redirect(url_for("login"))
        else:
            flash("Password does not match", "danger")
            return render_template("register.html")
    return render_template("register.html")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.permanent = True
        username = request.form.get('username')
        password = request.form.get('password')

        usernamedata = db.execute("SELECT username FROM users WHERE username=:username", {"username":username}).fetchone()
        passworddata = db.execute("SELECT password FROM users WHERE username=:username", {"username":username}).fetchone()
        if usernamedata is None:
            session["log"] = True
            flash('No Username', 'danger')
            return render_template('login.html')
        else:
            for passdata in passworddata:
                if sha256_crypt.verify(password, passdata):
                    flash('You are now logged in','success')
                    session['log'] = False
                    return redirect(url_for('home'))
                else:
                    flash('Wrong Password', 'danger')
                    return render_template('login.html')
    return render_template("login.html")

@app.route("/logout")
def logout():
    flash("You are now logged out", 'success')
    session['log']=True
    return redirect(url_for('login'))
@app.route("/calender")
def calendar():
    return render_template("calender.html")
@app.route("/rules")
def rules():
    return render_template("rules.html")


if __name__ == "__main__":
    app.run(debug=app.config["DEBUG"])


#Import Flask Library
from flask import Flask, render_template, request, session, url_for, redirect
import hashlib
import pymysql.cursors
from passlib.hash import sha256_crypt
import datetime
#Initialize the app from Flask
app = Flask(__name__)

#Configure MySQL
conn = pymysql.connect(host='localhost',
                       user='root',
                       password='',
                       db='findfolks',
                       charset='utf8mb4',
                       cursorclass=pymysql.cursors.DictCursor)
#Define a route to main page
@app.route('/')
def index():
	cursor = conn.cursor();
	currtime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	query = 'SELECT * FROM an_event WHERE datediff(start_time,%s)<=3 and datediff(start_time,%s)>=0 ORDER BY start_time DESC'
	cursor.execute(query, (currtime,currtime))
	data = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT distinct category,keyword FROM about'
	cursor.execute(query, ())
	data2 = cursor.fetchall()
	cursor.close()
	return render_template('index.html', posts=data, inters = data2)

@app.route('/interests', methods=['GET', 'POST'])
def interests():
	cursor = conn.cursor();
	category = request.form['category']
	keyword = request.form['keyword']
	query = 'SELECT distinct group_name,description FROM about,a_group WHERE category=%s and keyword=%s and about.group_id=a_group.group_id'
	cursor.execute(query, (category,keyword))
	data3 = cursor.fetchall()
	cursor.close()
	return render_template('interests.html', groups=data3)

#Define route for login
@app.route('/login')
def login():
	return render_template('login.html')

#Define route for register
@app.route('/register')
def register():
	return render_template('register.html')

#Authenticates the login
@app.route('/loginAuth', methods=['GET', 'POST'])
def loginAuth():
	#grabs information from the forms
	username = request.form['Username']
	password = request.form['Password']
	
	#cursor used to send queries
	cursor = conn.cursor()
	#executes query
	query = 'SELECT password FROM member WHERE username = %s'
	cursor.execute(query, (username))
	
	#stores the results in a variable
	data = cursor.fetchone()
	if(not data):
		error = 'Invalid login or username'
		return render_template('login.html', error=error)
	#use fetchall() if you are expecting more than 1 data row
	
	cursor.close()
	error = None

	if(sha256_crypt.verify(password, data['password'])):
		#creates a session for the the user
		#session is a built in
		session['username'] = username
		return redirect(url_for('home'))
	else:
		#returns an error message to the html page
		error = 'Invalid login or username'
		return render_template('login.html', error=error)

#Authenticates the register
@app.route('/registerAuth', methods=['GET', 'POST'])
def registerAuth():
	#grabs information from the forms
	username = request.form['Username']
	password = request.form['Password']
	firstname = request.form['Firstname']
	lastname = request.form['Lastname']
	email = request.form['e-mail']
	zipcode = request.form['zipcode']
	
	password2 = sha256_crypt.encrypt(password)
	#cursor used to send queries
	cursor = conn.cursor()
	#executes query
	query = 'SELECT * FROM member WHERE username = %s'
	cursor.execute(query, (username))
	
	#stores the results in a variable
	data = cursor.fetchone()
	#use fetchall() if you are expecting more than 1 data row
	error = None
	if(data):
		#If the previous query returns data, then user exists
		error = "This user already exists"
		return render_template('register.html', error = error)
	else:
		ins = 'INSERT INTO member VALUES(%s, %s, %s, %s, %s, %s)'
		cursor.execute(ins, (username, password2, firstname, lastname, email, zipcode))
		conn.commit()
		cursor.close()
		return render_template('index.html')

@app.route('/home')
def home():
	username = session['username']
	cursor = conn.cursor();
	query = 'SELECT ts, blog_post FROM blog WHERE username = %s ORDER BY ts DESC'
	cursor.execute(query, (username))
	data = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	currtime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	query = 'SELECT title,description,start_time,location_name,zipcode FROM an_event,sign_up WHERE datediff(start_time,%s)<=3 and datediff(start_time,%s)>=0 and sign_up.event_id=an_event.event_id and username=%s ORDER BY start_time DESC'
	cursor.execute(query, (currtime, currtime, username))
	data2 = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT e.event_id,title,description,start_time,location_name,zipcode,rating, (SELECT AVG(rating) FROM sign_up s WHERE e.event_id=s.event_id) "avg" FROM an_event e,sign_up WHERE datediff(start_time,%s)<0 and sign_up.event_id=e.event_id and username=%s ORDER BY start_time DESC'
	cursor.execute(query, (currtime, username))
	data3 = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT AVG(rating) as "avg" FROM sign_up WHERE event_id in (SELECT an_event.event_id FROM an_event,sign_up WHERE datediff(start_time,%s)<0 and datediff(start_time,%s)>-3 and sign_up.event_id=an_event.event_id and username=%s)'
	cursor.execute(query, (currtime, currtime, username))
	ratingdata = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT a_group.group_id,group_name,description,authorized FROM a_group,belongs_to WHERE username=%s and belongs_to.group_id=a_group.group_id ORDER BY group_id DESC'
	cursor.execute(query, (username))
	data4 = cursor.fetchall()
	cursor.close()
	for entry in data4:
		if(entry['authorized']==1):
			entry['authorized']="Yes"
		else:
			entry['authorized']="No"
	
	return render_template('home.html', username=username, posts=data, upevents=data2, pastevents=data3, ratingdata=ratingdata[0], groups=data4)
	
@app.route('/home/browse')
def browse():
	username = session['username']
	cursor = conn.cursor();
	currtime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	query = 'SELECT * FROM an_event WHERE event_id in(SELECT event_id FROM organize WHERE group_id in(SELECT distinct group_id FROM about WHERE category in (SELECT category FROM interested_in WHERE username=%s)and keyword in (SELECT keyword FROM interested_in WHERE username=%s)))and datediff(start_time,%s)>=0 ORDER BY start_time DESC'
	cursor.execute(query, (username, username, currtime))
	data = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT * FROM an_event WHERE datediff(start_time,%s)>=0 ORDER BY start_time DESC'
	cursor.execute(query, (currtime))
	data2 = cursor.fetchall()
	cursor.close()
	return render_template('browse.html', upevents=data, allevents=data2)

@app.route('/home/frievents')
def frievents():
	username = session['username']
	cursor = conn.cursor();
	currtime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	query = 'SELECT * FROM an_event WHERE event_id in(SELECT event_id FROM sign_up WHERE username in(SELECT friend_of FROM friend WHERE friend_to=%s)) and datediff(start_time,%s)>=0 ORDER BY start_time DESC'
	cursor.execute(query, (username,currtime))
	data = cursor.fetchall()
	cursor.close()
	
	cursor = conn.cursor();
	query = 'SELECT * FROM an_event WHERE datediff(start_time,%s)>=0 ORDER BY start_time DESC'
	cursor.execute(query, (currtime))
	data2 = cursor.fetchall()
	cursor.close()
	return render_template('frievents.html', upevents=data, allevents=data2)
	
@app.route('/home/rate', methods=['GET', 'POST'])
def rate():
	username = session['username']
	cursor = conn.cursor();
	eventid = request.form['eventid']
	rating = request.form['rating']
	currtime=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	query = 'SELECT * FROM an_event,sign_up WHERE datediff(start_time,%s)<0 and sign_up.event_id=an_event.event_id and sign_up.event_id=%s and username=%s ORDER BY start_time DESC'
	data = cursor.execute(query, (currtime, eventid, username))
	cursor.close()
	
	if(data and int(rating)>=0 and int(rating)<=5):
		cursor = conn.cursor();
		query = 'UPDATE sign_up SET rating=CAST(%s AS unsigned) WHERE event_id=%s and username=%s'
		cursor.execute(query, (rating, eventid, username))
		conn.commit()
		cursor.close()
	return redirect(url_for('home'))

@app.route('/home/createvent', methods=['GET', 'POST'])
def createvent():
	username = session['username']
	cursor = conn.cursor();
	groupid = request.form['groupid']
	title = request.form['title']
	description = request.form['description']
	start = request.form['start']
	end = request.form['end']
	location = request.form['location']
	zipcode = request.form['zipcode']
	
	if(groupid):
		query = 'SELECT * FROM belongs_to WHERE username=%s and authorized=1 and group_id=CAST(%s AS unsigned)'
		data = cursor.execute(query, (username, groupid))
	else:
		cursor.close()
		return redirect(url_for('home'))
	cursor.close()
	print(data)
	if(data):
		cursor = conn.cursor();
		query = 'INSERT INTO an_event (event_id, title, description, start_time, end_time, location_name, zipcode) VALUES((SELECT MAX(event_id) FROM organize)+1, %s, %s, %s, %s, %s, CAST(%s AS unsigned))'
		cursor.execute(query, (title, description, start, end, location, zipcode))
		conn.commit()
		query = 'INSERT INTO organize (event_id, group_id) VALUES((SELECT MAX(event_id) FROM an_event), CAST(%s AS unsigned))'
		cursor.execute(query, (groupid))
		conn.commit()
		cursor.close()
	return redirect(url_for('home'))
	
	
@app.route('/home/browse/signup', methods=['GET', 'POST'])
def signup():
	username = session['username']
	cursor = conn.cursor();
	eventid = request.form['eventid']
	query = 'SELECT * FROM sign_up WHERE event_id=%s and username=%s'
	data = cursor.execute(query, (eventid, username))
	cursor.close()
	
	if(not data):
		cursor = conn.cursor();
		query = 'INSERT INTO sign_up (event_id, username, rating) VALUES(%s, %s, 0)'
		cursor.execute(query, (eventid, username))
		conn.commit()
		cursor.close()
	return redirect(url_for('browse'))
	
@app.route('/post', methods=['GET', 'POST'])
def post():
	username = session['username']
	cursor = conn.cursor();
	blog = request.form['blog']
	query = 'INSERT INTO blog (blog_post, username) VALUES(%s, %s)'
	cursor.execute(query, (blog, username))
	conn.commit()
	cursor.close()
	return redirect(url_for('home'))

@app.route('/logout')
def logout():
	session.pop('username')
	return redirect('/')
		
app.secret_key = 'ihaveasecret'
#Run the app on localhost port 5000
#debug = True -> you don't have to restart flask
#for changes to go through, TURN OFF FOR PRODUCTION
if __name__ == "__main__":
	app.run();
	#app.run('127.0.0.1', 5000, debug = True)

import sys
sys.path.insert(0, 'srcs')
import webapp2
from bs4 import BeautifulSoup
from google.appengine.api import urlfetch
import datetime
import schedule
import jinja2
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from google.appengine.api import mail
import time
from google.appengine.ext import db
import re
import hashlib
import hmac
import random
from string import letters
from google.appengine.api import users

secret = 'kevinling0218'

template_dir = os.path.join(os.path.dirname(__file__),'templates/html')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)

currency = ['CNY','USD']
def get_content(currency_pair):
    url = "https://www.bloomberg.com/quote/"+str(currency_pair[0])+str(currency_pair[1])+":CUR"
    print "The url is: ", url
    source_code = urlfetch.fetch(url)
    soup = BeautifulSoup(source_code.content,'html.parser')
    price = soup.find('div',class_='price')
    quote = price.text

    print quote
    return quote


def send_email(user_email_address, currency_pair_list):

	# msg = MIMEMultipart('alternative')
	# msg['Subject'] = "Link"
	# msg['From'] = 'kevinling0218@gmail.com'
	# msg['To'] = 'kevinling0218@gmail.com'

	# # Create the body of the message (a plain-text and an HTML version).
	# text = "Hi!\nHow are you?\nHere is the link you wanted:\nhttp://www.python.org"
	# html = """\
	# <html>
	#   <head></head>
	#   <body>
	#     <p>Hi!<br>
	#        How are you?<br>
	#        Here is the <a href="http://www.python.org">link</a> you wanted.
	#     </p>
	#     <h1>The price today is: %s</h1>
	#   </body>
	# </html>
	# """ %str(get_content())

	# # Record the MIME types of both parts - text/plain and text/html.
	# part1 = MIMEText(text, 'plain')
	# part2 = MIMEText(html, 'html')
	# msg.attach(part1)
	# msg.attach(part2)
	# mail = smtplib.SMTP('smtp.gmail.com', 587)
	# mail.ehlo()
	# mail.starttls()
	# mail.login('kevinling0218@gmail.com','a0119051')
	# mail.sendmail(msg['From'], msg['To'],msg.as_string())
	# mail.close()

	# mail.send_mail(sender="kevinling0218@udacity-testing-178815.appspot.com",
	#                    to="kevinling0218@gmail.com",
	#                    subject="Your account has been approved",
	#                    body="""Dear Albert:

	# Your example.com account has been approved.  You can now visit
	# http://www.example.com/ and sign in using your Google Account to
	# access new features.

	# Please let us know if you have any questions.

	# The example.com Team
	# """)
    message = mail.EmailMessage(
    sender="kevinling0218@gmail.com",
    subject="The currency price information for today")

    message.to = user_email_address

    email_info = []

    for i in range(0,len(currency_pair_list)-1):
    	currency_pair = [currency_pair_list[i], currency_pair_list[i+1]]
    	currency_price = get_content(currency_pair)
    	email_info.append(currency_pair)
    	email_info.append(currency_price)
    	i = i + 2
    	print i, email_info


    message_1 = """Dear user:
    Here is the list of price for today:"""

    #message_2 = 

    message.body = """Dear user:
    Here is the list of price for today:

    The price of are: %s
	"""%str(email_info)
    message.send()

    print 'The message is sent as', email_info

# send_email('kevinling0218@gmail.com',['USD','EUR','SGD','CNY'])

# Seperate database between Email and Currency

# class Email(db.Model):
# 	email = db.EmailProperty(required = True)

# class Currency(parent = Email):
# 	currency_1 = db.StringProperty(required = True)
# 	currency_2 = db.StringProperty(required = True)
# 	alert_price = db.FloatProperty(required = False)


def hash_str(s):
	return hmac.new(secret, s).hexdigest()

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_pw_hash(name, pw, salt= None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (salt,h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)    


# function to get long list to currency pair list

def into_pairs(long_list):
	pair_list = []
	i = 0
	while i in range (0,len(long_list)-1):
		pair_list.append([long_list[i],long_list[i+1]])
		i = i+2
	return pair_list

# Combined database

class User_Info(db.Model):
	user = db.StringProperty(required = True)
	currency_list = db.ListProperty(str,required = True)


class User(db.Model):
    name = db.StringProperty(required=True)
    email = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name = ', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash = pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u




class Handler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write (*args, **kwargs)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self,user):
    	self.set_secure_cookie('user_id', str(user.key().id()))
    	print "The user is logining in with user id of", str(user.key().id())

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        print "there is a valid user for this request"
        self.user = uid and User.by_id(int(uid))
        print self.user


class LoginPage(Handler):
	def get(self):
		self.render("Login_Page.html")
		#visits = self.request.cookies.get('visits', '0')

		#self.response.headers.add_header('Set-Cookie', 'visits=%s' % visits)

	def post(self):

		user_login = self.request.get('login_button')
		user_signup = self.request.get('signup_button')

		if user_signup:
			print "The user is signing up"
			have_error = False
			self.username = self.request.get('username')
			self.password = self.request.get('password')
			self.confirm_password = self.request.get('confirm_password')
			self.email = self.request.get('email')

			error_msg_signup = dict()

			if not valid_username(self.username):
				error_msg_signup['error_username'] = "The username is not valid"
				have_error = True
				print "The username is", self.username
				print "User name didnt pass"

			if not valid_password(self.password):
				error_msg_signup['error_password'] = "The password must be at least 3 characters"
				have_error = True
				print "password didnt pass"

			if not valid_email(self.email):
				error_msg_signup['error_email'] = "Only NUS domain email is allowed"
				have_error = True
				print "email didnt pass"

			elif self.password != self.confirm_password:
				error_msg_signup['error_verify'] = 'The password does not match'
				have_error = True
				print "validation didnt pass"

			if have_error:
				self.render("Login_Page.html", **error_msg_signup)

			else:
				print "signup success"
				self.sign_up_success()

		if user_login:
			login_username = self.request.get('login_username')
			login_password = self.request.get('login_password')

			print "username:", login_username
			print "password", login_password
			login_user = User.login(login_username,login_password)

			if login_user:
				print "login success"
				self.login(login_user)
				self.redirect('/currency')

			else:
				error_msg_login = "Your username or password is wrong"
				self.render("Login_Page.html",error_login=error_msg_login)


	def sign_up_success(self, *args, **kwargs):
		u = User.by_name(self.username)
		if u:
			error_existing_user = "This account has already been registered, please login"
			self.render("Login_Page.html", error_username = error_existing_user)
		else:
			print "Now redirect to the currency page"
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.redirect('/currency')

class MainPage(Handler):
	def get(self):
		# Get the login user
		print "The user is logining in with username of", self.user.name
		login_user = self.user.name

		# Get all the submitted information and filter out
		user_data = User_Info.all().filter("user =", login_user)
		login_user_currency = user_data.get()
		print login_user_currency
		#login_user_currency_pair = into_pairs(login_user_currency.currency_list)
		#print login_user_currency_pair
		self.render('currency_pair.html', login_user = login_user)
		
		# schedule.every(5).seconds.do(send_email)
		# send_email()
		print 'the app is working'
		# while True:
		# 	schedule.run_pending()
		# 	time.sleep(1)


	def post(self):
		print 'post working'
		# Get user Email
		#user_email = self.request.get('email_address')
		login_user = self.user.name
		user_currency = self.request.get('all_currency_list')
		user_currency_list = user_currency.split(',')
		print "your currency list is:", user_currency
		print 'your currency pair is: ', into_pairs(user_currency_list) 

		error_msg = dict()
		#confirmation_url = create_new_user_confirmation(user_address)
		if login_user and user_currency:
			"Now putting data into database"
			have_error = False

			# if not valid_email(user_email):
			# 	have_error = True
			# 	error_msg['error_email'] = "The Email must be an NUS domain"
			# 	self.render('Homepage.html', **error_msg)
			# else:
			user_info = User_Info(user = login_user, currency_list = user_currency_list)
			user_info.put()


			self.write("success")
			#self.render('submitted.html', email= user_email, currency = user_currency)

		# sender_address = 'kevinling0218@gmail.com'
		# subject = 'The daily price of SGD/CNY'
		# body = """Thank you for creating an account. The daily price is %s"""%str(get_content())
		# mail.send_mail(sender_address, user_address, subject, body)


		# Testing data base


class Submission (Handler):
	def get(self):
		self.render('submitted.html')


class Cron (Handler):
	def get(self):
		user_info = db.GqlQuery("SELECT * FROM User_Info")
		for each_info in user_info:
			send_email(each_info.email, each_info.currency_list)
		print "The cron is working"

class EmailHandler(Handler):
	'''Test function for Cron'''
	def get(self):
		email_info = db.GqlQuery("SELECT * FROM Email")
		for email in email_info[0]:
			send_email(email)

# Form validation
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@u.nus.edu$')
def valid_email(email):
	return email and EMAIL_RE.match(email)

# Handler Mapping
	
app = webapp2.WSGIApplication([
    ('/', LoginPage),('/currency', MainPage),('/submitted', Submission),('/task/summary', Cron)], debug=True)

def test_printing():
	print "The app is working"



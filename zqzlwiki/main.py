#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from google.appengine.ext import db
from string import letters

import webapp2
import jinja2
import time
import re
import random
import hashlib
import hmac
import os

# initialize jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

#global variables
user = ""
secret = "shit"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# general handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params["user"] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; Path=/" % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and USER_INFO.by_id(int(uid))

# wiki db and user db
class Wiki_DB(db.Model):
    title   = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
# user info
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class USER_INFO(db.Model):
    uname = db.StringProperty(required=True)
    pword = db.StringProperty(required=True)
    email = db.StringProperty()
    signDate = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, uid):
        return USER_INFO.get_by_id(uid, parent = users_key())
    @classmethod
    def by_name(cls, name):
        u = USER_INFO.all().filter('uname = ', name).get()
        return u
    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return USER_INFO(parent = users_key(),
                         uname  = name,
                         pword  = pw_hash,
                         email  = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pword):
            return u

# handlers
class WikiPage(Handler):
    def render_front(self, wiki_content=""):
        leftString = "login"
        leftLink = "/login"
        rightString = "signup"
        rightLink = "/signup"

        if self.user:
            leftString = "edit"
            leftLink = "/edit"
            rightString = "logout"
            rightLink = "/logout"

        self.render("frontpage.html", wiki_content=wiki_content,
            leftString=leftString, leftLink=leftLink,
            rightString=rightString, rightLink=rightLink)

    def get(self, pagename):
        subject = pagename[1:]
        wikis = db.GqlQuery("SELECT * FROM Wiki_DB "
                            "WHERE title=:1", subject)
        if pagename != "/" and wikis.get() is None:
            self.redirect("/_edit/%s" % subject)
        elif pagename == "/":
            self.render_front()
        else:
            for w in wikis:
                self.render_front(wiki_content = w.content)
                break

    def post(self):
        wiki_content = self.request.get("wiki_content")
        self.render_front(wiki_content)

# sign up part
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(Handler):

    def get(self):
        self.render("signup.html", u_error="", p_error="")

    def post(self):
        uname = self.request.get("user_id")
        pword = self.request.get("password")
        email = self.request.get("email")

        u_error = ""
        p_error = ""

        if uname and pword:
            u = USER_INFO.register(uname, pword, email)
            u.put()

            self.login(u)
            self.redirect("/")

        else:
            if uname == "":
                u_error = "Please give us a user name"
            if pword == "":
                p_error = "Please input a valid password"
            self.render("signup.html",u_error=u_error, p_error=p_error)

class Login(Handler):

    def get(self):
        self.render("login.html", u_error="", p_error="")

    def post(self):
        uname = self.request.get("user_id")
        pword = self.request.get("password")

        u_error = ""
        p_error = ""

        if uname == "":
            u_error = "Please input your user name"
            self.render("login.html", u_error=u_error, p_error=p_error)
            return
        if pword == "":
            p_error = "Please input your password"
            self.render("login.html", u_error=u_error, p_error=p_error)
            return

        u_info = db.GqlQuery("SELECT * FROM USER_INFO "
                             "WHERE uname = :1", uname)
        if u_info.get() is None:
            u_error = "User Name Not Found"
            self.render("login.html", u_error=u_error, p_error=p_error)
            return

        u = USER_INFO.login(uname, pword)

        if u:
            self.login(u)
            self.redirect("/")
        else:
            p_error = "Wrong Password"
            self.render("login.html", u_error=u_error, p_error=p_error)

class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/')

class EditPage(Handler):

    def get(self, wiki_title):
        subject = wiki_title[1:]
        self.render("edit_wiki.html", wiki_title=subject, new_wiki="", error="")

    def post(self, title):
        subject = title[1:]
        new_wiki = self.request.get("new_wiki")
        if new_wiki:
            wiki = Wiki_DB(title=subject, content=new_wiki)
            wiki.put()

#            print "Redirect to /%s" % subject
            time.sleep(.1)
            self.redirect("/%s" % subject)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               ],
                               debug=True)

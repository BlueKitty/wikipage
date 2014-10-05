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

import webapp2
import jinja2
import time
import os

# initialize jinja
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#class Art(db.Model):
#    title   = db.StringProperty(required = True)
#    art     = db.TextProperty(required = True)
#    created = db.DateTimeProperty(auto_now_add = True)
class Wiki_DB(db.Model):
    title   = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class USER_INFO(db.Model):
    uname = db.StringProperty(required=True)
    pword = db.StringProperty(required=True)
    email = db.StringProperty()
    signDate = db.DateTimeProperty(auto_now_add = True)

user=""
class WikiPage(Handler):
    def render_front(self, wiki_content=""):
        global user
        leftString = "login"
        leftLink = "/login"
        rightString = "signup"
        rightLink = "/signup"

        if user:
            leftString = "edit"
            leftLink = "/edit"
            rightString = "logout"
            rightLink = "/logout"

        self.render("frontpage.html", wiki_content=wiki_content, leftString=leftString, leftLink=leftLink, rightString=rightString, rightLink=rightLink)

    def get(self, pagename):
        subject = pagename[1:]
        wikis = db.GqlQuery("SELECT * FROM Wiki_DB "
                            "WHERE title=:1", subject)

#        print "pagename is %s, subject is %s" % (pagename, subject)
#        print '------------------------------------------'

        if pagename != "/" and wikis.get() is None:
#            print "Cond 1"
#            print pagename
#            print wikis.get()
            self.redirect("/_edit/%s" % subject)
        elif pagename == "/":
#            print "Cond 2"
            self.render_front()
        else:
#            print "Cond 3"
            for w in wikis:
                self.render_front(wiki_content = w.content)
                break

    def post(self):
        wiki_content = self.request.get("wiki_content")
        self.render_front(wiki_content)

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
            u = USER_INFO(uname = uname, pword = pword, email = email)
            u.put()
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
        u_pass = u_info.get().pword

        if pword == u_pass:
            self.redirect("/")
        else:
            p_error = "Wrong Password"
            self.render("login.html", u_error=u_error, p_error=p_error)

class Logout(Handler):

    def get(self):
        pass

class EditPage(Handler):

    def get(self):
        pass

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

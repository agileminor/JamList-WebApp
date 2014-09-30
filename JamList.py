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

#
# items that need to be updated tagged with CHECK
#
import cgi
from google.appengine.api import memcache
from google.appengine.api import mail
import re
import webapp2
import os
import jinja2
import hashlib
import hmac
import random
import string
import logging
from GenSec import return_secret

#SECRET = "thisissecret"  # use for testing only
SECRET = return_secret()  # test to see if local import works, do not add GenSec to git
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def escape_html(s):
    return cgi.escape(s, quote=True)


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def make_salt(length=5):
    random.seed()
    return "".join(random.sample(string.letters, length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class Song(db.Model):
    name = db.StringProperty(required=True)
    song_key = db.StringProperty(required=False)
    lyrics = db.TextProperty(required=False)
    notes = db.TextProperty(required=False)
    public = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, uid, user):
        return Song.get_by_id(uid, parent=user.key())  # need to change to use current users id as parent

    @classmethod
    def by_title(cls, song_title):
        u = Song.all().filter('title =', song_title).get()
        return u

    @classmethod
    #def register(cls, name,key,lyrics,notes, user):
    def register(cls, name, key, lyrics, notes, user, public="False"):
        return Song(parent=user.key(),  # CHECK proper way to specify parent is another object or a string i.e. name
                    name=name,
                    song_key=key,
                    lyrics=lyrics,
                    notes=notes,
                    public=public)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    email = db.StringProperty(required=False)
    song_ids = db.ListProperty(int, indexed=False, default=[])

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())  # CHECK - NEED TO ADD CACHE HERE SOMEHOW

    @classmethod
    def by_name(cls, username):
        u = memcache.get("user_" + username)
        if not u:
            #logging.error("cache miss in by_name for " + username)
            u = User.all().filter('username =', username).get()
            if u:
                #logging.error("db hit after cache miss in by_name for " + username)
                memcache.set("user_"+username, u)
            else:
                pass
                #logging.error("db miss after cache miss in by_name for " + username)
        return u

    @classmethod
    def register(cls, username, pw, email=None):
        pw_hash = make_pw_hash(username, pw)
        return User(parent=users_key(),
                    username=username,
                    pw_hash=pw_hash,
                    email=email,
                    song_ids=[])

    @classmethod
    def login(cls, username, pw):
        #logging.error("checking login for " + username)
        u = cls.by_name(username)
        if u and valid_pw(username, pw, u.pw_hash):
            return u

# is the song class better of being linked to User by a list of song_ids
# or using user = db.ReferenceProperty(User, collection_name='songs' ? see https://developers.google.com/appengine/articles/modeling


class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.render("jam_front.html")

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
#        return check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))  # CHECK need to add cache here somehow

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.user = None

    def initialize(self, *a, **kw):
#        logging.error("in initialize")
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
#        self.user = User.by_id(int(uid))

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'


class LoginHandler(MainHandler):
    def get(self):
        self.render("jam_login.html")

    def post(self):
        username_error = ""
        password_error = ""
        # action = self.request.get("submitButton")
        # if action = "Login": # do login activities
        # elif: action = "Reset Password": # send reset link
        #   reset_link = # construct unique link, reset_(d+)
        #   reset_address = # get user email address
        #   mail.send_mail(sender="Do Not Reply <no_reply@jamlist.appspotmail.com>",
        #                           to="<" + reset_address + ">",
        #                           subject="Password reset for JamList",
        #                           body="""Please click on this link to reset your password - """ + reset_link
        #                           )
        #
        # else: pass # do nothing
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        check_username = valid_username(self.username)
        check_password = valid_password(self.password)
        if not (check_username and check_password):
            if not check_username:
                username_error = "That's not a valid username."
            else:
                username_error = ""
#                self.username = escape_html(self.username)
            if not check_password:
                password_error = "That wasn't a valid password."
            else:
                password_error = ""

        else:
            # need to extract user id, check password
            login_check = User.login(self.username, self.password)
            if login_check:
                self.login(login_check)
                self.redirect("/main")
            else:
                error_dict = dict(username=self.username)
                error_dict["error_message"] = "Invalid Login"
                self.render("jam_login.html", **error_dict)


class LogoutHandler(MainHandler):
    def get(self):
            #logging.error("in logout")
            self.logout()
            self.redirect("/")


class SignupHandler(MainHandler):
    def get(self):
        self.render("jam_register.html")

    def post(self):
        is_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        signup_dict = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            signup_dict['error_username'] = "Invalid Username"
            is_error = True

        if not valid_password(self.password):
            signup_dict['error_password'] = "Invalid Password"
            is_error = True
        elif self.password != self.verify:
            signup_dict['error_verify'] = "Passwords must match"
            is_error = True

        if not valid_email(self.email):
            signup_dict['error_email'] = "Invalid Email Address"
            is_error = True

        if is_error:
            self.render('jam_register.html', **signup_dict)
        else:
            self.done()

    def done(self):
        #make sure the user doesn't already exist
        #CHECK - add email to user email, only register user after click on link
        proposed_user = User.by_name(self.username)
        if proposed_user:
            msg = 'That user already exists.'
            self.render('jam_register.html', error_username=msg)
        else:
            proposed_user = User.register(self.username, self.password, self.email)
            memcache.set("user_"+self.username, proposed_user)
            proposed_user.put()

            self.login(proposed_user)
            self.redirect('/main')


class ListHandler(MainHandler):
    def get(self):
        if self.user:
            username = self.user.username
            self.current_songs = []
            for song_id in self.user.song_ids:
                self.current_songs.append(Song.by_id(int(song_id), self.user))
            self.render('main.html', username=username, current_songs=self.current_songs)
        else:
            self.redirect('/')


class NewSongHandler(MainHandler):
    def get(self):
        if self.user:
            username = self.user.username
            songlist = self.user.song_ids
            self.render('newsong.html', username=username, songlist=songlist)

    def post(self):
        is_error = False  # CHECK add error checking for song inputs
        self.song_title = self.request.get('song_title')
        self.song_key = self.request.get('song_key')
        self.song_lyrics = escape_html(self.request.get('song_lyrics')).replace('\n','<br>')
        self.song_notes = self.request.get('song_notes')
        if is_error:
            pass
        else:
            self.done()

    def done(self):
        proposed_song = Song.register(self.song_title, self.song_key, self.song_lyrics, self.song_notes, self.user)
        proposed_song.put()
        new_song = Song.by_title(self.song_title)
        song_id = proposed_song.key().id()
        memcache.set("song_"+str(song_id), proposed_song)
        self.user.song_ids.append(song_id)
        self.user.put()
        memcache.set("user_"+self.user.username, self.user)
        self.redirect('/main')


class SongHandler(MainHandler):
    def get(self, song_id):
        if self.user:
            username = self.user.username
            #logging.error("found user")
            current_song = memcache.get(str("song_"+str(song_id)))  # this works, unless memcache reset
            if not current_song:
                #logging.error('song not found in cache')
                current_song = Song.get_by_id(int(song_id), self.user.key())  # CHECK this doesn't work - should this be Song.by_id instead of Song.get_by_id?
                if current_song:
                    memcache.set("song_"+str(song_id), current_song)
                if not current_song:
                    #logging.error('song not found in database')
                    pass
            if current_song:
                if int(song_id) in self.user.song_ids:
                    self.render('song.html', username=username, current_song=current_song)
                else:
                    #logging.error('song not found in users songs, id = %s' % song_id)
                    self.redirect('/main')
            else:
                self.redirect('/main')
        else:
            #logging.error("no user")
            self.redirect('/')


class EditSongHandler(MainHandler):
    def get(self, song_id):
        if self.user:
            username = self.user.username
            current_song = memcache.get(str("song_"+str(song_id)))
            if not current_song:
                #logging.error('song not found in cache')
                current_song = Song.get_by_id(int(song_id), self.user.key()) # should this be Song.by_id instead of Song.get_by_id?
                if current_song:
                    memcache.set("song_"+str(song_id), current_song)
                if not current_song:
                    #logging.error('song not found in database')
                    pass
            if current_song:
                if int(song_id) in self.user.song_ids:
                    #logging.error('song not found in users songs, id = %s' % song_id)
                    self.current_song = current_song
                    self.render('editsong.html', username=username, current_song=current_song)
                else:
                    self.redirect('/main')
            else:
                self.redirect('/main')
        else:
            self.redirect('/')

    def post(self, song_id):
        is_error = False # CHECK add error checking for song inputs
        current_song = memcache.get(str("song_"+str(song_id)))
        current_song.name = self.request.get('song_title')
        current_song.name = self.request.get('song_title')
        current_song.song_key = self.request.get('song_key')
        current_song.lyrics = self.request.get('song_lyrics')
        current_song.notes = self.request.get('song_notes')
        if is_error:
            pass
        else:
            self.done(current_song)

    def done(self, current_song):
        current_song.put()
        memcache.set("song_"+str(current_song.key().id()), current_song)
        self.redirect('/main')


class DeleteSongHandler(MainHandler):
    def get(self, song_id):
        #logging.error("in delete song")
        if self.user:
            username = self.user.username
            #logging.error("found user")
            current_song = memcache.get(str("song_"+str(song_id)))
            if not current_song:  # CHECK - change to make redirect at end, in case of fall through
                #logging.error('song not found in cache')
                current_song = Song.get_by_id(int(song_id), self.user.key())
                if current_song:
                    memcache.set("song_"+str(song_id), current_song)
                if not current_song:
                    #logging.error('song not found in database')
                    pass
            if current_song:
                if int(song_id) in self.user.song_ids:
                    memcache.delete("song_"+str(song_id))  # delete song from cache CHECK does this need to validate that song is in cache?
                    self.user.song_ids.remove(int(song_id))  # update User to remove song id
                    current_song.delete()  # delete song from database
                    self.user.put()  # update user in database
                    memcache.set("user_"+self.user.username,self.user)  # update user in cache
                    # CHECK - should I add these updated song/user to the classmethods?
                else:
                    #logging.error('song not found in users songs, id = %s' % song_id)
                    self.redirect('/main')
            else:
                self.redirect('/main')
            self.redirect('/main')
        else:
            #logging.error("no user")
            self.redirect('/')


class PasswordResetHandler(MainHandler):
    def get(self, code):
        pass
        # pseudo-code
        #check if code is valid:
        #    check if data code created is less than one day old
        #        get new password for user
        #send to invalid webpage

    def put(self, code):
        pass
        # pseudo-code
        # get new password and update user given by code
        # erase code in database

app = webapp2.WSGIApplication([('/', MainHandler),
                                ('/register',SignupHandler),
                                ('/login',LoginHandler),
                                ('/logout',LogoutHandler),
                                ('/main',ListHandler),
                                ('/newsong',NewSongHandler),
                                (r'/(\d+)',SongHandler),
                                (r'/_edit(\d+)',EditSongHandler),
                                (r'/_delete(\d+)',DeleteSongHandler),
                               ],
                               debug=True)
app.run()

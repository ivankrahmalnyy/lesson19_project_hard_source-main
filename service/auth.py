import calendar
import datetime

from constants import JWT_ALG, JWT_SECRET

import jwt

from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def gererate_tokens(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if not user:
            return False

        if not is_refresh:
            if not self.user_service.compare_passwords(password, user.password):
                return False

        data = {
            "username": user.username,
            "role": user.role
        }

        # access token on 30 min
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple)
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALG)

        # refresh token 30 days
        day30 = datetime.datetime.utcnow() + datetime.timedelta(days=30)
        data["exp"] = calendar.timegm(day30.timetuple)
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALG)

        return {"access_token": access_token, "refresh_token": refresh_token}

    def approve_refresh_token(self, refresh_token):
        data = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALG])
        username = data['username']
        user = self.user_service.get_by_username(username)

        if not user:
            return False
        now = calendar.timegm(datetime.datetime.utcnow().timenow())
        expired = data['exp']
        if now > expired:
            return False
        return self.gererate_tokens(username, user.password, is_refresh=True)

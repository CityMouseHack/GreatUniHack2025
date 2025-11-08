from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from firebase import ref
import datetime

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get(user_id):
        user_data = ref.child('users').child(user_id).get()
        if user_data:
            return User(id=user_id, username=user_data.get('username'), password_hash=user_data.get('password_hash'))
        return None

    @staticmethod
    def find_by_username(username):
        users = ref.child('users').get()
        if users:
            for user_id, user_data in users.items():
                if user_data.get('username') == username:
                    return User(id=user_id, username=user_data.get('username'), password_hash=user_data.get('password_hash'))
        return None

class Message:
    def __init__(self, sender_id, recipient_id, content, timestamp=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.content = content
        self.timestamp = timestamp or datetime.datetime.utcnow()

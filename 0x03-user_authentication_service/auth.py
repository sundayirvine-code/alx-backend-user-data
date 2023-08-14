#!/usr/bin/env python3
"""
Authentication Module
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid

def _hash_password(password: str) -> bytes:
    """
    Hash the input password using bcrypt and return the salted hash as bytes.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def _generate_uuid() -> str:
    """
    Generate a new UUID and return it as a string.
    """
    return str(uuid.uuid4())
    
class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user and return a User object.
        """
        try:
            existing_user = self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Check if the provided login credentials are valid.
        """
        try:
            user = self._db.find_user_by(email=email)
            hashed_password = user.hashed_password
            provided_password = password.encode('utf-8')
            return bcrypt.checkpw(provided_password, hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session for the user and return the session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

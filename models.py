from sqlalchemy import Column, ForeignKey
from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
# from sqlalchemy.sql import functions as func
from sqlalchemy import create_engine

from passlib.apps import custom_app_context as pwd_context
import random
import string
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

Base = declarative_base()
secret_key = ''.join(random.choice(
    string.ascii_uppercase + string.digits) for x in xrange(32))


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32))
    picture = Column(String(250))
    # to look up with the unique email
    email = Column(String(250), index=True)
    password_hash = Column(String(250))
    blog = Column(String(250), default="My new blog")
    created = Column(Integer)
    blog_public = Column(Boolean, default=False)

    def hash_password(self, password):
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'username': self.username,
            'picture': self.username,
            'email': self.email,
            'blog': self.blog,
            'created': self.created,
            'blog_public': self.blog_public,
        }

    @staticmethod  # because user is only known when the token is decoded
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            # valid token, but expired
            return None
        except BadSignature:
            # invalid token
            return None
        user_id = data['id']
        return user_id


class Post(Base):
    __tablename__ = 'post'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    subject = Column(String(250), default='No title')
    content = Column(Text)
    short_content = Column(String(250))
    created = Column(Integer)
    last_modified = Column(Integer)
    likes = Column(Integer, default=0)
    publish_consent = Column(Boolean, default=0)
    category = Column(String(50))
    published = Column(Integer)

    # take the first 12 words to present in the main page.
    def get_short_content(self):
        s = self.content.split()[:12]
        s = ' '.join(s)
        s += "...... [Continue Reading]"
        self.short_content = s

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'blog_id': self.blog_id,
            'subject': self.subject,
            'content': self.content,
            'short_content': self.short_content,
            'created': self.created,
            'last_modified': self.last_modified,
            'publish_consent': self.publish_consent,
        }




engine = create_engine('sqlite:///metablog.db')

Base.metadata.create_all(engine)

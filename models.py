from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy import Boolean, Integer, String, Text, Float
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

# User to Post = one to many, foreing key on Post, relationship on User


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(32))
    picture = Column(String(250))
    # to look up with the unique email
    email = Column(String(250), index=True)
    password_hash = Column(String(250))

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


class Blog(Base):
    __tablename__ = 'blog'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    blog_name = Column(String(250), default="Name your blog")
    public_username = Column(String(50))
    short_intro = Column(String(300),
                         default="Write a little bit about your blog")
    profile_img = Column(String(300))
    location = Column(String(250))
    created = Column(Integer)
    last_modified = Column(Integer)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'blog_name': self.blog_name,
            'public_username': self.public_username,
            'short_intro': self.short_intro,
            'profile_img': self.profile_img,
            'location': self.location,
            'created': self.created,
            'last_modified': self.last_modified,
        }


class Post(Base):
    __tablename__ = 'post'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    blog_id = Column(Integer, ForeignKey('blog.id'))
    blog = relationship(Blog)
    subject = Column(String(250))
    content = Column(Text)
    short_content = Column(String(250))
    created = Column(Integer)
    last_modified = Column(Integer)
    likes = Column(Integer, default=0)
    publish = Column(String(50))
    attached_img = Column(String(300))

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
            'user_id': self.user_id,
            'blog_id': self.blog_id,
            'subject': self.subject,
            'content': self.content,
            'short_content': self.short_content,
            'created': self.created,
            'last_modified': self.last_modified,
            'likes': self.likes,
            'publish': self.publish,
            'attached_img': self.attached_img,
        }


class Likes(Base):
    __tablename__ = 'likes'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    post_id = Column(Integer, ForeignKey('post.id'), nullable=False)
    user = relationship(User)
    post = relationship(Post)

    # there can be only one pair of user_id, post_id
    __table_args__ = (UniqueConstraint('user_id', 'post_id'),)


class Comment(Base):
    __tablename__ = 'comment'
    id = Column(Integer, primary_key=True)
    post_id = Column(Integer, ForeignKey('post.id'))
    post = relationship(Post)
    commented_ts = Column(Float)
    commented_dt = Column(String(250))
    commenter = Column(String(32), ForeignKey('user.username'))
    user = relationship(User)
    comment_body = Column(Text)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'id': self.id,
            'post_id': self.post_id,
            'commented_ts': self.commented_ts,
            'commented_dt': self.commented_dt,
            'commenter': self.commenter,
            'comment_body': self.comment_body,
        }


engine = create_engine('sqlite:///bloghost.db')

Base.metadata.create_all(engine)

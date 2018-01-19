from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, User, Blog, Post, Comment, Likes

engine = create_engine('sqlite:///bloghost.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(username="Tiny Rob", email="tenny@tiny.com")


User2 = User(username="Frontend Ninja", email="ninja@front.com")


User3 = User(username="Jersey Girl", email="girl@jersey.com")

session.add(User1)
session.add(User2)
session.add(User3)

# Create dummy user's blogs
Blog1 = Blog(user_id=2,
             blog_name="dream a little dream",
             public_username="dreaming ninja",
             short_intro="writing about my everyday thoughts",
             location="LA, USA")
Blog2 = Blog(user_id=3,
             public_username="Jersey Girl",
             location="NY, USA")

session.add(Blog1)
session.add(Blog2)

# Create dummy user's posts
Post1 = Post(user_id=2,
             blog_id=1,
             subject="Lorem ipsum",
             content="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
             publish="no"
             )
Post1.get_short_content()
Post2 = Post(user_id=3,
             blog_id=2,
             subject="Blah Blah",
             content="Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
             publish="etc",
             likes=2)
Post2.get_short_content()
session.add(Post1)
session.add(Post2)

Comment1 = Comment(post_id=2,
                   commenter="Tiny Rob",
                   commented_ts=1514329311.27646,
                   commented_dt='2017-12-26 23:01:51',
                   comment_body='What a cool story!')

Comment2 = Comment(post_id=2,
                   commenter='Frontend Ninja',
                   commented_ts=1514329719.58813,
                   commented_dt='2017-12-26 23:08:39',
                   comment_body='I agree! such a cool stroy!!')
session.add(Comment1)
session.add(Comment2)

likes1 = Likes(post_id=2,
               user_id=1)

likes2 = Likes(post_id=2,
               user_id=2)

session.add(likes1)
session.add(likes2)

session.commit()

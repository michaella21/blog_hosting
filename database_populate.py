from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, User, Project

engine = create_engine('sqlite:///projectsCatalog.db')
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

session.add(User1)
session.commit()

# Projects for the user1
proj1 = Project(user_id=1, name="Unique Blog", main_language="python")
proj1.description = "Very very unique blog written from scratch" + \
    "which includes lots of fun info about myself!"

session.add(proj1)
session.commit()

proj2 = Project(user_id=1, name="Mock Online Store", main_language="PHP")
proj2.description = "Online store equipped with all the necessary function" +\
    " but without actual items to sell"

session.add(proj2)
session.commit()

proj3 = Project(user_id=1, name="Cool Portfolio", main_language="HTML/CSS")
proj3.description = "HTML page showing all my cool projects"

session.add(proj3)
session.commit()

User2 = User(username="Frontend Ninja", email="ninja@front.com")

session.add(User2)
session.commit()

# Projects for the user2
proj4 = Project(user_id=2, name="Movie Reviews", main_language="HTML/CSS")
proj4.description = "List of movies that I watch along with movietrilers, etc"

session.add(proj4)
session.commit()

proj5 = Project(user_id=2, name="Interactive Resume",
                main_language="JavaScript")
proj5.description = "Not anymore regular resume, it's now fancied up with" +\
    "all new Interactive functions!"

session.add(proj5)
session.commit()


print "added menu items!"

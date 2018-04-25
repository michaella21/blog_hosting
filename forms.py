# FlaskForm is a session secure form with CSRF protection
from flask_wtf import FlaskForm as BaseForm
from wtforms import RadioField, TextAreaField
from wtforms import TextField, SubmitField, FileField
from wtforms import validators


class NewPostForm(BaseForm):
    subject = TextField("Subject",
                        [validators.DataRequired("Please enter the subject of\
                        your post.")])
    content = TextAreaField("Content",
                            [validators.DataRequired("You cannot submit\
                             empty content.")])
    publish = RadioField("Would you like to publish it? Then, choose a right\
                         category please.",
                         choices=[('review', 'Book/Movie/TV Show reviews'),
                                  ('food', 'Food/Restaurant'),
                                  ('politics', 'Politics'),
                                  ('travel', 'Travel'),
                                  ('animal', 'Cute animals'),
                                  ('life', 'Daily Life'),
                                  ('etc', "Uncategorized"),
                                  ('no', "No, I want to keep it private")])

    image = FileField('Would you like to attach any image file to your post?\
                       pdf, jpg, jpeg, png, gif files upto 16MB accepted')
    submit = SubmitField("submit")


class CommentForm(BaseForm):
    comment = TextAreaField("Leave your comment",
                            [validators.DataRequired("You cannot submit\
                            empty content.")])
    submit = SubmitField("submit")


class BlogForm(BaseForm):
    blog_name = TextField("Would you like to change your blog name?",
                          [validators.Length(min=1, max=250)])
    public_username = TextField("You can change the username shown to other\
     users", [validators.Length(min=4, max=32)])
    short_intro = TextField("Add one line introduction to your blog",
                            [validators.Length(max=300)])
    image = FileField("Upload your profile picture.\
                        pdf, jpg, jpeg, png, gif files upto 16MB accepted)")
    location = TextField("Your location? (city, country)")

    submit = SubmitField("submit")

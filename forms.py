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

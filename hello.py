from flask import Flask, render_template, flash
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# ფლასკის სახელი
app = Flask(__name__)

db = SQLAlchemy()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql:///root:password123@localhost/our_users'
app.config['SECRET_KEY'] = '12345678'

db.init_app(app)





# კლასი ბაზებისთვის
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return '<Name %r>' % self.name



class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Submit")
    

# კლასი ფორმებისთვის
class NamerForm(FlaskForm):
    name = StringField("Whats Your Name", validators=[DataRequired()])
    submit = SubmitField("Submit")


# რუთი ახალი მომხმარებლისთვის
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            user = Users(name=form.name.data, email=form.email.data)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        flash('წარმატებულად დაემატა!')
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html", form=form, name=name, our_users=our_users)


@app.route("/")
def hello_world():
    first_name = "Beka"
    favorite_pizza = ["Cheese", "Apple", 44]
    return render_template("index.html", first_name=first_name, favorite_pizza=favorite_pizza)

# # ფილტრები ჯინჯასთვის:
# # safe - ბოლდი ჯინჯადან (<strong></strong>)- ის მაგივრად
# # capitalize - დიდი პირველი ასო
# # lower - პატარა ასოები
# # upper - დიდი ასოები
# # title - პირველი ასოები იზრდება
# # trim - შლის Space-ებს
# # striptags - შლის ყველა ეფექტს.
# # reverse - შებრუნება

# # localhost:5000/user/Beka
@app.route('/user/<name>')
def user(name):
    return render_template("user.html", user_name=name)

# ERROR PAGE
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# NAME PAGE
@app.route('/name', methods=['GET', 'POST'])
def namepage():
    name = None
    form = NamerForm()
    # ვალიდაცია
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("წარმატებულია!!!")
    return render_template('name.html', name = name, form = form)




with app.app_context():
    db.create_all()
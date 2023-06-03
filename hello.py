from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError, TextAreaField
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor, CKEditorField
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename
from sqlalchemy import MetaData
import uuid as uuid
import os

# ფლასკის სახელი
app = Flask(__name__)
ckeditor = CKEditor(app)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(metadata=MetaData(naming_convention=convention))
migrate = Migrate()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db'
app.config['SECRET_KEY'] = '12345678'

db.init_app(app)
migrate.init_app(app, db, render_as_batch=True)

# ფლასკის ავტორიზაცია
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# ადმინ პანელი
@app.route('/admin')
@login_required
def admin():
    id = current_user.id
    if id == 1:
        return render_template("admin.html")
    else:
        flash("თქვენ არ გაქვთ უფლება შეხვიდეთ ადმინ პანელზე!")
        return redirect(url_for('dashboard'))


# ძიების დაკავშირება ნავიგაციასთან
@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


@app.route('/search', methods=["POST"])
def search():
    form = SearchForm()
    posts = Posts.query
    if form.validate_on_submit():
        # მონაცემის გადატანა ბაზაში
        post.searched = form.searched.data

        posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
        posts = posts.order_by(Posts.title).all()

        return render_template("search.html",
                               form=form,
                               searched=post.searched,
                               posts=posts)


class LoginForm(FlaskForm):
    username = StringField("მომხმარებელი", validators=[DataRequired()])
    password = PasswordField("პაროლი", validators=[DataRequired()])
    submit = SubmitField("დასტური")


class SearchForm(FlaskForm):
    searched = StringField("ძიება", validators=[DataRequired()])
    submit = SubmitField("დასტური")


# ავტორიზაციის გვერდი
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # პაროლის შემოწმება
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("ავტორიზაცია წარმატებულია!")
                return redirect(url_for('dashboard'))
            else:
                flash("პაროლი არასწორია!")
        else:
            flash('ასეთი მომხმარებელი არ არსებობს!')
    return render_template('login.html', form=form)


# გამოსვლის გვერდი
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("თქვენ გამოხვედით პანელიდან...")
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        name_to_update.about_author = request.form['about_author']
        name_to_update.profile_pic = request.files['profile_pic']

        # სურათის სახელი
        pic_filename = secure_filename(name_to_update.profile_pic.filename)
        # უნიკალური ID
        pic_name = str(uuid.uuid1()) + "_" + pic_filename
        # სურათის შენახვა
        saver = request.files['profile_pic']

        # ვუცვლი ფორმატს ბაზაში შესანახად
        name_to_update.profile_pic = pic_name

        try:
            db.session.commit()
            flash("მომხმარებელი წარმატებით შეიცვალა!")
            return render_template("dashboard.html",
                                   form=form,
                                   name_to_update=name_to_update)
        except:
            flash("შეცდომა! - სცადეთ თავიდან")
            return render_template("dashboard.html",
                                   form=form,
                                   name_to_update=name_to_update)
    else:
        return render_template("dashboard.html",
                               form=form,
                               name_to_update=name_to_update,
                               id=id)
    return render_template('dashboard.html')


# კლასი ბლოგებისთვის
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    # author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    slug = db.Column(db.String(255))
    # ვაკავშირებ პოსტებს მომხმარებლებთან
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))


# კლასი ბლოგის ფორმებისთვის
class PostForm(FlaskForm):
    title = StringField("სათაური", validators=[DataRequired()])
    # content = StringField("კონტენტი", validators=[DataRequired()], widget=TextArea())
    content = CKEditorField("კონტენტი", validators=[DataRequired()])
    # author = StringField("ავტორი")
    slug = StringField("სხვა", validators=[DataRequired()])
    submit = SubmitField("დადასტურება")


@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster.id:

        try:
            db.session.delete(post_to_delete)
            db.session.commit()

            flash("ბლოგი წაშლილია!")

            posts = Posts.query.order_by(Posts.date_posted)
            return render_template("posts.html", posts=posts)


        except:

            flash("შეცდომა! - სცადეთ თავიდან!")

            posts = Posts.query.order_by(Posts.date_posted)
            return render_template("posts.html", posts=posts)
    else:
        flash("თქვენ არ გაქვთ წაშლის უფლება!")

        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)


@app.route('/posts')
def posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template("posts.html", posts=posts)


@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html', post=post)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        # post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data

        db.session.add(post)
        db.session.commit()
        flash("ბლოგი შეცვლილია...")
        return redirect(url_for('post', id=post.id))

    if current_user.id == post.poster_id:
        form.title.data = post.title
        # form.author.data = post.author
        form.slug.data = post.slug
        form.content.data = post.content
        return render_template('edit_post.html', form=form)
    else:
        flash("თქვენ არ გაქვთ უფლება შეცვალოთ პოსტი!")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)


@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()

    if form.validate_on_submit():
        poster = current_user.id
        post = Posts(title=form.title.data, content=form.content.data, poster_id=poster, slug=form.slug.data)

        form.title.data = ''
        form.content.data = ''
        # form.author.data = ''
        form.slug.data = ''

        db.session.add(post)
        db.session.commit()

        flash("ბლოგი დადასტურებულია წარმატებით!")

    return render_template("add_post.html", form=form)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if id == current_user.id:
        user_to_delete = Users.query.get_or_404(id)
        name = None
        form = UserForm()

        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash("მომხმარებელი წაშლილია!")

            our_users = Users.query.order_by(Users.date_added)
            return render_template("add_user.html",
                                   form=form,
                                   name=name,
                                   our_users=our_users)

        except:
            flash("შეცდომა, გთხოვთ სცადეთ თავიდან")
            return render_template("add_user.html",
                                   form=form, name=name, our_users=our_users)
    else:
        flash('თქვენ არ გაქვთ წაშლის უფლება!')
        return redirect(url_for('dashboard'))


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        name_to_update.favorite_color = request.form['favorite_color']
        name_to_update.username = request.form['username']
        try:
            db.session.commit()
            flash("მომხმარებელი შეცვლილია!")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update)
        except:
            flash("შეცდომა, გთხოვთ სცადეთ თავიდან!")
            return render_template("update.html",
                                   form=form,
                                   name_to_update=name_to_update)
    else:
        return render_template("update.html",
                               form=form,
                               name_to_update=name_to_update,
                               id=id)


# კლასი ბაზებისთვის
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    favorite_color = db.Column(db.String(120))
    about_author = db.Column(db.Text(), nullable=True)
    profile_pic = db.Column(db.String(), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    # პაროლი

    password_hash = db.Column(db.String(128))
    posts = db.relationship('Posts', backref='poster')

    # + რაოდენობის პოსტები მომხმარებელზე

    @property
    def password(self):
        raise AttributeError('წაკითხვა შეუძლებელია!')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name


class UserForm(FlaskForm):
    name = StringField("სახელი", validators=[DataRequired()])
    username = StringField("მომხმარებელი", validators=[DataRequired()])
    email = StringField("ელფოსტა", validators=[DataRequired()])
    favorite_color = StringField("ფსევდონიმი")
    about_author = TextAreaField("ავტორის შესახებ")
    password_hash = PasswordField('პაროლი', validators=[DataRequired(),
                                                        EqualTo('password_hash2', message='Passwords Must Match!')])
    password_hash2 = PasswordField('გაიმეორე პაროლი', validators=[DataRequired()])
    profile_pic = FileField('პროფილის სურათი')
    submit = SubmitField("დადასტურება")


# პაროლის კლასი
class PasswordForm(FlaskForm):
    email = StringField("თქვენი ელფოსტა", validators=[DataRequired()])
    password_hash = PasswordField("თქვენი პაროლი", validators=[DataRequired()])
    submit = SubmitField("დადასტურება")


# კლასი ფორმებისთვის
class NamerForm(FlaskForm):
    name = StringField("თქვენი სახელი", validators=[DataRequired()])
    submit = SubmitField("დადასტურება")


# რუთი ახალი მომხმარებლისთვის
@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            # user = Users(name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data)
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data,
                         favorite_color=form.favorite_color.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash.data = ''
        flash('წარმატებულად დაემატა!')
    our_users = Users.query.order_by(Users.date_added)
    return render_template("add_user.html", form=form, name=name, our_users=our_users)


@app.route("/")
def hello_world():
    first_name = "Beka"
    favorite_pizza = ["Cheese", "Apple", 44]
    return render_template("index.html", first_name=first_name, favorite_pizza=favorite_pizza)


# # # localhost:5000/user/Beka
@app.route('/user/<name>')
def user(name):
    return render_template("user.html", user_name=name)


# ERROR PAGE
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route('/name', methods=['GET', 'POST'])
def namepage():
    name = None
    form = NamerForm()
    # ვალიდაცია
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        flash("წარმატებულია!!!")
    return render_template('name.html', name=name, form=form)


# ვტესტავ პაროლს
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None
    password = None
    pw_to_check = None
    passed = None
    form = PasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data

        form.email.data = ''
        form.password_hash.data = ''

        pw_to_check = Users.query.filter_by(email=email).first()

        passed = check_password_hash(pw_to_check.password_hash, password)

    return render_template("test_pw.html",
                           email=email,
                           password=password,
                           pw_to_check=pw_to_check,
                           passed=passed,
                           form=form)


with app.app_context():
    db.create_all()

# # ფილტრები ჯინჯასთვის:
# # safe - ბოლდი ჯინჯადან (<strong></strong>)- ის მაგივრად (აშორებს HTML-სთვის ზედმეტ სიმბოლოებს)
# # capitalize - დიდი პირველი ასო
# # lower - პატარა ასოები
# # upper - დიდი ასოები
# # title - პირველი ასოები იზრდება
# # trim - შლის Space-ებს
# # striptags - შლის ყველა ეფექტს.
# # reverse - შებრუნება

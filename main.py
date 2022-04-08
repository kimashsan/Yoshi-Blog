from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm,CreateUserForm,LoginForm,CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.orm import relationship
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False,
                    use_ssl=False, base_url=None)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #Create reference to the User object, the "posts" refers to the posts property in the User class.

    # This shows that Blogpost.auther is related to User.post (these two properties are not exposed in DB)
    # also shows that these field are used to refer to properties of another class.

    # Sqlalchemy knows these two fields are related now(especially ORM need this other than foregin Key)
    # and will upadte each as the other is upadted

    # https: // stackoverflow.com / questions / 39869793 / when - do - i - need - to - use - sqlalchemy - back - populates
    author = relationship("User", back_populates="posts")
    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    #***************Child Relationship*************#
    text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
# login_manager.login_view = "login"
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

@app.route('/register',methods=['POST','GET'])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email= form.email.data,
            password = hash_and_salted_password,
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",form = form)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user == None:
            flash('That mail dose not exist.Please try it again')
            return render_template("login.html", form=form)
        elif not check_password_hash(user.password, form.password.data):
            flash('That password dose not correct.Please try it again')
            return render_template('login.html', form=form)
        else:
            login_user(user)
            return redirect(url_for('get_all_posts', current_user=current_user))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
        logout_user()
        # remove the username from the session if it's there
        return redirect(url_for('get_all_posts'))



@app.route("/post/<int:post_id>",methods=['POST','GET'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect('/login')
        requested_post = BlogPost.query.get(post_id)
        new_comment = Comment(
            text=form.comment.data,
            author_id=current_user.id,
            post_id=requested_post.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return render_template("post.html", post=requested_post, form=form)
    return render_template("post.html", post=requested_post,
                           form=form, current_user=current_user)

def adminonly(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return wrapper

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post",methods=['POST','GET'])
@adminonly
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>",methods=['POST','GET'])
@adminonly
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>",methods=['POST','GET'])
@adminonly
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)

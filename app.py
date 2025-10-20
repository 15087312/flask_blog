from sqlalchemy import create_engine, Column, Integer, String
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import random
import string
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

from models import db, User, Post
from forms import LoginForm, RegisterForm, PostForm
# 在现有import后添加
from flask import request, current_app
from werkzeug.utils import secure_filename
import os

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-this-with-a-secure-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

# 邮件配置
app.config['MAIL_SERVER'] = 'mail.qq.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '1019097627@qq.com'
app.config['MAIL_PASSWORD'] = '134679852Zh'
app.config['MAIL_DEFAULT_SENDER'] = '1019097627@qq.com'
# 添加 SECURITY_PASSWORD_SALT 配置
app.config['SECURITY_PASSWORD_SALT'] = 'your-security-salt-here'

db.init_app(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 用于标记表是否已创建的标志
tables_created = False

@app.before_request
def create_tables():
    global tables_created
    if not tables_created:
        db.create_all()
        tables_created = True

@app.route('/')
def index():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/captcha')
def captcha_image():
    # 生成随机验证码
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    session['captcha'] = captcha_text

    # 创建验证码图片
    img = Image.new('RGB', (120, 40), color=(255, 255, 255))
    d = ImageDraw.Draw(img)

    # 使用默认字体（或者指定字体文件）
    try:
        font = ImageFont.truetype('arial.ttf', 24)
    except:
        font = ImageFont.load_default()

    d.text((10, 10), captcha_text, fill=(0, 0, 0), font=font)

    # 添加干扰线
    for _ in range(5):
        x1 = random.randint(0, 120)
        y1 = random.randint(0, 40)
        x2 = random.randint(0, 120)
        y2 = random.randint(0, 40)
        d.line((x1, y1, x2, y2), fill=(0, 0, 0), width=1)

    # 将图片保存到内存中并返回
    byte_io = BytesIO()
    img.save(byte_io, 'PNG')
    byte_io.seek(0)

    return send_file(byte_io, mimetype='image/png')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # 验证验证码
        if form.captcha.data != session.get('captcha', ''):
            flash('验证码错误')
            return render_template('register.html', form=form)

        # 检查用户名和邮箱是否已存在
        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            flash('用户名或邮箱已存在')
            return render_template('register.html', form=form)

        user = User(
            username=form.username.data,
            email=form.email.data,
            password=generate_password_hash(form.password.data)
        )
        db.session.add(user)
        db.session.commit()

        # 发送验证邮件
        token = generate_confirmation_token(user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email_confirmation.html', confirm_url=confirm_url)
        send_email(user.email, '请验证您的邮箱地址', html)

        flash('注册成功！请检查您的邮箱进行验证。')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, body=form.body.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('发布成功')
        return redirect(url_for('index'))
    return render_template('post.html', form=form)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # 处理头像上传
        if 'avatar' not in request.files:
            flash('没有选择文件')
            return redirect(request.url)

        file = request.files['avatar']
        if file.filename == '':
            flash('没有选择文件')
            return redirect(request.url)

        if file:
            filename = secure_filename(file.filename)
            if not allowed_file(filename):
                flash('不允许的文件类型')
                return redirect(request.url)

            # 创建uploads目录如果不存在
            upload_dir = os.path.join(current_app.root_path, 'static/uploads')
            os.makedirs(upload_dir, exist_ok=True)

            # 保存文件
            file_path = os.path.join(upload_dir, filename)
            file.save(file_path)

            # 更新用户头像信息
            current_user.avatar = filename
            db.session.commit()
            flash('头像上传成功')
            return redirect(url_for('profile'))

    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)
from itsdangerous import URLSafeTimedSerializer

def generate_confirmation_token(email):
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email
from flask import render_template
from flask_mail import Message
def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('确认链接无效或已过期。')
        return redirect(url_for('index'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.email_confirmed:
        flash('账户已验证。请登录。')
    else:
        user.email_confirmed = True
        db.session.add(user)
        db.session.commit()
        flash('您已成功验证邮箱。谢谢！')
    return redirect(url_for('login'))
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404
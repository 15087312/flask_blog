from sqlalchemy import create_engine, Column, Integer, String
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
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

def allowed_file(filename):  # 检查文件扩展名是否允许上传
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
app = Flask(__name__)
app.config['SECRET_KEY'] = 'replace-this-with-a-secure-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

# 邮件配置
app.config['MAIL_SERVER'] = 'smtp.qq.com'  # QQ邮箱SMTP服务器地址
app.config['MAIL_PORT'] = 465  # QQ邮箱SSL加密端口号
app.config['MAIL_USE_SSL'] = True  # 启用SSL加密连接
app.config['MAIL_USERNAME'] = '1019097627@qq.com'  # 发件人邮箱账号
app.config['MAIL_PASSWORD'] = 'wbzmxucplmwebbfe'  # QQ邮箱授权码(非登录密码)
app.config['MAIL_DEFAULT_SENDER'] = '1019097627@qq.com'  # 默认发件人地址
app.config['SECURITY_PASSWORD_SALT'] = 'your-security-salt-here'  # 密码哈希盐值

# 邮件功能函数
def generate_confirmation_token(email):  # 生成邮箱验证令牌
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):  # 验证并解析邮箱验证令牌
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email

def send_email(to, subject, template):  # 发送HTML格式邮件
    """
    发送HTML格式邮件
    :param to: 收件人邮箱地址
    :param subject: 邮件主题
    :param template: HTML邮件内容
    :return: 发送成功返回True，失败返回False
    """
    msg = Message(
        subject,  # 邮件主题
        recipients=[to],  # 收件人列表
        html=template,  # HTML邮件内容
        sender=app.config['MAIL_DEFAULT_SENDER']  # 发件人地址
    )
    try:
        mail.send(msg)  # 发送邮件，默认超时10秒
    except Exception as e:
        app.logger.error(f"邮件发送失败: {str(e)}")  # 记录错误日志
        return False  # 返回发送失败状态
    return True  # 返回发送成功状态

db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):  # 加载当前登录用户
    return User.query.get(int(user_id))


# 用于标记表是否已创建的标志
tables_created = False

@app.before_request
def create_tables():  # 确保数据库表已创建
    global tables_created
    if not tables_created:
        db.create_all()
        tables_created = True

@app.route('/')
def index():  # 显示首页文章列表
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template('index.html', posts=posts)

@app.route('/captcha')
def captcha_image():  # 生成验证码图片
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
def register():  # 处理用户注册
    form = RegisterForm()
    if form.validate_on_submit():
        session_captcha = session.get('captcha', '').upper()
        input_captcha = form.captcha.data.upper() if form.captcha.data else ''
        if session_captcha != input_captcha:
            flash('验证码错误，请重新输入')
            return render_template('register.html', form=form)

        # 检查用户名和邮箱是否已存在
        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            flash('用户名或邮箱已存在')
            return render_template('register.html', form=form)

        # 先检查但不提交到数据库
        user = User(
            username=form.username.data,
            email=form.email.data,
            email_confirmed=False  # 初始状态为未验证
        )
        user.password = form.password.data  # 使用password setter自动哈希

        # 发送验证邮件
        token = generate_confirmation_token(user.email)  # 生成加密令牌
        confirm_url = url_for('confirm_email', token=token, _external=True)  # 生成确认链接
        html = render_template('email_confirmation.html', confirm_url=confirm_url)  # 渲染邮件模板
        if not send_email(user.email, '请验证您的邮箱地址', html):  # 发送验证邮件
            flash('邮件发送失败，请稍后再试', 'error')  # 发送失败提示
            return render_template('register.html', form=form)  # 返回注册页面

        # 临时保存用户信息到session
        session['pending_user'] = {
            'username': user.username,
            'email': user.email,
            'password_hash': user.password_hash
        }

        flash('验证邮件已发送，请检查您的邮箱完成注册。')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():  # 处理用户登录
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(
            title=form.title.data,
            body=form.body.data,
            price=form.price.data,
            status=form.status.data,
            author=current_user
        )
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

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('确认链接无效或已过期。')
        return redirect(url_for('index'))

    # 从session获取临时用户信息
    pending_user = session.get('pending_user')
    if not pending_user or pending_user['email'] != email:
        flash('验证失败，请重新注册。')
        return redirect(url_for('register'))

    # 创建并保存用户
    user = User(
        username=pending_user['username'],
        email=pending_user['email'],
        password_hash=pending_user['password_hash'],
        email_confirmed=True
    )
    db.session.add(user)
    db.session.commit()

    # 清除临时信息
    session.pop('pending_user', None)

    flash('您已成功完成注册！请登录。')
    return redirect(url_for('login'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.id)
            reset_url = url_for('reset_token', token=token, _external=True)
            html = render_template('reset_email.html', reset_url=reset_url)
            send_email(user.email, '密码重置请求', html)
        flash('如果该邮箱已注册，您将收到密码重置邮件')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user_id = verify_reset_token(token)
    if not user_id:
        flash('无效或过期的令牌', 'danger')
        return redirect(url_for('reset_request'))

    user = User.query.get(user_id)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        flash('密码已更新！您现在可以登录', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

def generate_reset_token(user_id, expiration=3600):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps({'user_id': user_id}, salt='password-reset-salt')

def verify_reset_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, salt='password-reset-salt', max_age=3600)
        return data['user_id']
    except:
        return None

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)
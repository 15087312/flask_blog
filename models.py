from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # 存储哈希值而非明文
    email_confirmed = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(120), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)  # 用户状态(活跃/封禁)
    last_login = db.Column(db.DateTime)  # 最后登录时间

    @property
    def password(self):
        raise AttributeError('密码不可读')

    @password.setter
    def password(self, password):
        # 生成密码哈希值
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        # 验证密码是否正确
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='available')  # available/sold/reserved
    is_approved = db.Column(db.Boolean, default=False)  # 审核状态
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    views = db.Column(db.Integer, default=0)  # 浏览次数
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
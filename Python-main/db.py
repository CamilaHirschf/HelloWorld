from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import app
from sqlalchemy import text


db = SQLAlchemy()


class User(db.Model, UserMixin):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def drop_user_table():
    with db.engine.connect() as connection:
        query = text("DROP TABLE IF EXISTS user")
        connection.execute(query)

def reset_database(app):
    with app.app_context():
        drop_user_table()
        db.create_all()



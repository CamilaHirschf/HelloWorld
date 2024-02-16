from datetime import timedelta

# Configuraciones de la aplicación
class Config:
    SECRET_KEY = 'Kns2o7Cb6hhRB0vSIwMj'
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/test.db'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=1)
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
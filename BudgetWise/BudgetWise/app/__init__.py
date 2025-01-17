from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

# Inițializarea extensiilor
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

# Funcția de încărcare a utilizatorului
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Returnează utilizatorul pe baza ID-ului

def create_app():
    app = Flask(__name__)

    # Configurare aplicație
    app.config.from_pyfile('../instance/config.py')  # Asigură-te că ai calea corectă către config.py

    # Inițializare extensii
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)  # Inițializează LoginManager

    # Setează ruta pentru autentificare
    login_manager.login_view = 'auth.login'

    # Înregistrează Blueprint-urile
    from .routes import main, auth  # Importă blueprint-urile main și auth
    app.register_blueprint(main)
    app.register_blueprint(auth, url_prefix='/auth')  # Înregistrează blueprint-ul auth cu un prefix

    return app

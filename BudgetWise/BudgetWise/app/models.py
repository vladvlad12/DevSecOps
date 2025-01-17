from . import db  # Importă instanța db din __init__.py
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin  # Importă UserMixin


class User(db.Model, UserMixin):  # Moștenește UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Adăugăm câmpul pentru secretul 2FA
    two_factor_secret = db.Column(db.String(32), nullable=True)  # Secretul 2FA
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    def __init__(self, username, password):
        self.username = username
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='scrypt')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Expense(db.Model):
    __tablename__ = 'expense'
    
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    
    # Adăugăm user_id pentru a lega cheltuielile de utilizator
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Referință la User
    
    # Adăugăm backref pentru a putea accesa cheltuielile unui utilizator
    user = db.relationship('User', backref='expenses', lazy=True)

    expense_permissions = db.relationship('ExpensePermission', backref='expense_item', lazy=True)

    def __repr__(self):
        return f"<Expense {self.description}>"

class ExpensePermission(db.Model):
    __tablename__ = 'expense_permission'
    id = db.Column(db.Integer, primary_key=True)
    expense_id = db.Column(db.Integer, db.ForeignKey('expense.id'), nullable=False)  # Referință la Expense
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Referință la User
    permission_type = db.Column(db.String(50), nullable=False)  # Tipul permisiunii: 'viewer' sau 'editor'
    
    expense = db.relationship('Expense', backref='related_permissions', lazy=True)  # Nume diferit pentru backref
    user = db.relationship('User', backref='permissions', lazy=True)

    def __repr__(self):
        return f"<ExpensePermission {self.user.username} - {self.permission_type}>"


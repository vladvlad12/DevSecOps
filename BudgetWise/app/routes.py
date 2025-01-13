from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .models import User, Expense
from . import db
from werkzeug.security import check_password_hash, generate_password_hash

from functools import wraps
from datetime import datetime
import pyotp
import qrcode
import os
from flask import current_app
main = Blueprint('main', __name__)
auth = Blueprint('auth', __name__)

CATEGORIES = ['Mâncare', 'Băutură', 'Facturi', 'Transport', 'Distracție', 'Altele']

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Trebuie sa fi logat.", "warning")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function
    
@main.route('/', methods=['GET', 'POST'])
@login_required
def home():
    category_filter = request.args.get('category')
    user_id = session['user_id']  # Preia ID-ul utilizatorului curent

    # Filtrarea cheltuielilor pe baza ID-ului utilizatorului curent
    if category_filter:
        expenses = Expense.query.filter_by(user_id=user_id, category=category_filter).all()
    else:
        expenses = Expense.query.filter_by(user_id=user_id).all()  # Preia doar cheltuielile utilizatorului curent

    categories = CATEGORIES

    return render_template('index.html', expenses=expenses, categories=categories, selected_category=category_filter)


@main.route('/add-expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        description = request.form['description']
        try:
            amount = float(request.form['amount'])
            if amount <= 0:
                flash("Suma trebuie sa fie un numar pozitiv.", "danger")
                return redirect(url_for('main.add_expense'))
        except ValueError:
            flash("Suma invalida. Trebuie sa fie un numar.", "danger")
            return redirect(url_for('main.add_expense'))

        category = request.form['category']
        date_str = request.form['date']
        try:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Data invalida. Folositi YYYY-MM-DD", "danger")
            return redirect(url_for('main.add_expense'))

        # Asociază cheltuiala cu utilizatorul curent
        expense = Expense(description=description, amount=amount, category=category, date=date, user_id=session['user_id'])
        db.session.add(expense)
        db.session.commit()

        flash("Cheltuiala adaugata cu succes!", "success")
        return redirect(url_for('main.home'))

    return render_template('add_expense.html', categories=CATEGORIES)

@main.route('/delete-expense/<int:id>', methods=['POST'])
@login_required
def delete_expense(id):
    expense = Expense.query.get(id)
    if expense and expense.user_id == session['user_id']:  # Verifică dacă cheltuiala aparține utilizatorului curent
        db.session.delete(expense)
        db.session.commit()
        flash("Cheltuiala stearsa cu succes!", "success")
    else:
        flash("Cheltuiala nu poate fi stearsă sau nu ai permisiunea.", "error")
    
    return redirect(url_for('main.home'))

@main.route('/edit-expense/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_expense(id):
    expense = Expense.query.get(id)
    if not expense:
        flash("Cheltuiala nu mai exista!", "error")
        return redirect(url_for('main.home'))

    if request.method == 'POST':
        expense.description = request.form['description']
        try:
            expense.amount = float(request.form['amount'])
            if expense.amount <= 0:
                flash("Suma trebuie sa fie un numar pozitiv.", "danger")
                return redirect(url_for('main.edit_expense', id=expense.id))
        except ValueError:
            flash("Suma invalida. Trebuie sa fie un numar.", "danger")
            return redirect(url_for('main.edit_expense', id=expense.id))

        expense.category = request.form['category']
        date_str = request.form['date']
        try:
            expense.date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("Data invalida. Folositi YYYY-MM-DD.", "danger")
            return redirect(url_for('main.edit_expense', id=expense.id))

        db.session.commit()

        flash("Expense updated successfully!", "success")
        return redirect(url_for('main.home'))

    return render_template('edit_expense.html', expense=expense, categories=CATEGORIES)

@main.route('/share-expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def share_expense(expense_id):
    expense = Expense.query.get(expense_id)
    if not expense or expense.user_id != current_user.id:
        flash("Nu ai permisiunea de a partaja această cheltuială.", "danger")
        return redirect(url_for('main.home'))

    if request.method == 'POST':
        shared_user = User.query.filter_by(username=request.form['username']).first()
        if not shared_user:
            flash("Utilizatorul nu a fost găsit.", "danger")
            return redirect(url_for('main.share_expense', expense_id=expense_id))

        permission_type = request.form['permission_type']
        # Crează permisiunea
        permission = ExpensePermission(
            user_id=shared_user.id, expense_id=expense.id, permission_type=permission_type)
        db.session.add(permission)
        db.session.commit()

        flash(f"Permisiune acordată {shared_user.username} pentru cheltuiala {expense.description} cu rol {permission_type}.", "success")
        return redirect(url_for('main.home'))

    return render_template('share_expense.html', expense=expense)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Găsește utilizatorul în baza de date
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id  # Salvează utilizatorul în sesiune

            # Verifică dacă 2FA este activat
            if user.two_factor_enabled:
                totp = pyotp.TOTP(user.two_factor_secret)
                return redirect(url_for('main.two_factor'))  # Mergi la pagina de 2FA
            else:
                return redirect(url_for('main.home'))  # Redirecționează la pagina principală
        else:
            return 'User sau parola gresite!'  # Mesaj de eroare pentru login invalid
    return render_template('login.html')  # Returnează pagina de login


@main.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if request.method == 'POST':
        code = request.form['code']
        user = User.query.get(session['user_id'])
        totp = pyotp.TOTP(user.two_factor_secret)

        if totp.verify(code):
            # Dacă codul este valid, autentifică utilizatorul
            return redirect(url_for('home'))
        else:
            return 'Cod 2FA invalid'

    return render_template('two_factor.html')
    
@auth.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash("Ai fost deconectat cu succes.", "info")
    return redirect(url_for('auth.login'))
    
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Verifică dacă utilizatorul există deja
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return 'Utilizatorul exista deja'

        # Creează un nou utilizator
        new_user = User(username=username, password=password)

        # Creează un secret pentru utilizatorul respectiv
        totp = pyotp.TOTP(pyotp.random_base32())
        new_user.two_factor_secret = totp.secret

        # Salvează utilizatorul în baza de date
        db.session.add(new_user)
        db.session.commit()

        # Generează un cod QR pentru Google Authenticator
        provisioning_uri = totp.provisioning_uri(username, issuer_name="BudgetWise - Morozan")

        # Creează și salvează imaginea QR
        img = qrcode.make(provisioning_uri)
        img.save(os.path.join('app', 'static', '2fa_qrs', f'{new_user.id}_qr.png'))  # Folosește 'new_user' în loc de 'user'

        return render_template('register_success.html', qr_code_path=f'2fa_qrs/{new_user.id}_qr.png')
    return render_template('register.html')


@auth.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    user = User.query.get(session['user_id'])  # Preia utilizatorul curent

    # Verifică dacă 2FA este deja activat
    if user.two_factor_enabled:
        flash("2FA este deja activat! Il poti dezactiva mai jos.", "info")
        return render_template('enable_2fa.html', disable=True)  # Afișează formularul de dezactivare

    if request.method == 'POST':
        # Dacă formularul a fost trimis, salvează secretul în baza de date și activează 2FA
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(request.form['2fa_code']):
            user.two_factor_enabled = True
            db.session.commit()
            flash("2FA activat cu succes!", "success")
            return redirect(url_for('main.home'))
        else:
            flash("Cod 2Fa inavlid. Incearca din nou!.", "danger")
            return redirect(url_for('auth.enable_2fa'))

    # Dacă nu s-a trimis încă formularul, generează secretul și codul QR
    if not user.two_factor_secret:
        user.two_factor_secret = pyotp.random_base32()  # Generează secretul
        db.session.commit()

    totp = pyotp.TOTP(user.two_factor_secret)  # Creează un obiect TOTP cu secretul utilizatorului
    uri = totp.provisioning_uri(user.username, issuer_name="BudgetWise - Morozan")  # Generează URL-ul de configurare
    img = qrcode.make(uri)  # Generează codul QR

    # Verifică și creează directorul pentru fișierele 2FA dacă nu există
    qr_code_dir = os.path.join(current_app.static_folder, '2fa_qrs')
    if not os.path.exists(qr_code_dir):
        os.makedirs(qr_code_dir)

    # Salvează codul QR pe server pentru a fi afisat în template
    img_path = f"static/2fa_qrs/{user.id}_qr.png"
    img.save(os.path.join(current_app.static_folder, '2fa_qrs', f"{user.id}_qr.png"))

    return render_template('enable_2fa.html', qr_code_path=img_path)



@auth.route('/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    user = User.query.get(session['user_id'])  # Preia utilizatorul curent

    # Verifică dacă 2FA este activat
    if not user.two_factor_enabled:
        flash("2FA nu este activat!", "info")
        return redirect(url_for('main.home'))  # Redirecționează utilizatorul către pagina principală

    # Verifică codul 2FA pentru dezactivare
    if request.method == 'POST':
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(request.form['2fa_code']):
            user.two_factor_enabled = False
            db.session.commit()
            flash("2FA a fost dezactivat cu succes.", "success")
            return redirect(url_for('main.home'))
        else:
            flash("Cod 2FA invalid. Incearca din nou!.", "danger")
            return redirect(url_for('auth.enable_2fa'))

    return redirect(url_for('main.home'))
@auth.route('/regenerate-2fa', methods=['POST'])
@login_required
def regenerate_2fa():
    user = User.query.get(session['user_id'])  # Preia utilizatorul curent

    # Generează un nou secret TOTP
    user.two_factor_secret = pyotp.random_base32()
    db.session.commit()

    totp = pyotp.TOTP(user.two_factor_secret)
    uri = totp.provisioning_uri(user.username, issuer_name="BudgetWise - Morozan")
    img = qrcode.make(uri)

    # Verifică și creează directorul pentru fișierele 2FA dacă nu există
    qr_code_dir = os.path.join(current_app.static_folder, '2fa_qrs')
    if not os.path.exists(qr_code_dir):
        os.makedirs(qr_code_dir)

    # Salvează fișierul QR
    img_path = os.path.join(qr_code_dir, f"{user.id}_qr.png")
    img.save(img_path)

    flash("Cod QR regenerat cu succes.", "success")
    return redirect(url_for('auth.enable_2fa'))
@main.route('/two_factor_verify', methods=['POST'])
def two_factor_verify():
    code = request.form['code']
    user = User.query.get(session['user_id'])
    totp = pyotp.TOTP(user.two_factor_secret)

    if totp.verify(code):
        # If the code is valid, redirect to home
        flash("Autetificarea 2FA a fost efectuata cu succes!", "success")
        return redirect(url_for('main.home'))
    else:
        flash("Cod 2FA invalid. Incearca din nou.", "danger")
        return redirect(url_for('main.two_factor'))

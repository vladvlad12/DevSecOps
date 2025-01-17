from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Crează un utilizator
    user = User(username='admin')  # Doar setăm username-ul
    user.set_password('admin')  # Setăm parola folosind funcția set_password
    db.session.add(user)
    db.session.commit()

    print("User creeat!")

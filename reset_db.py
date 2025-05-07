import os
from flask import Flask
from models import db

app = Flask(__name__, instance_relative_config=True)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'zero_trust.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Ensure the instance folder exists
os.makedirs(app.instance_path, exist_ok=True)

with app.app_context():
    # This will drop all tables and recreate them
    print("Dropping all tables...")
    db.drop_all()
    print("Creating all tables with the correct schema...")
    db.create_all()
    print("Database reset complete!")
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from .database import SessionLocal, engine, Base
from .models import User, PasswordHistory, Document, SecurityEvent, BlockedIP
from .auth import hash_password

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Check if admin already exists
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        print("[*] Creating Primary SOC Administrator: 'admin'...")
        admin = User(
            id=str(uuid.uuid4()),
            username="admin",
            email="admin@apexshield.corp",
            full_name="Lead Security Administrator",
            department="Cybersecurity SOC",
            role="Admin",
            clearance_level="Top Secret",
            password_hash=hash_password("Admin@Apex2026!"),
            is_active=True,
            is_locked=False,
            must_reset_password=False
        )
        db.add(admin)
        db.commit()

    # Check if Sarah Connor exists
    sarah = db.query(User).filter(User.username == "sarah.connor").first()
    if sarah:
        sarah.role = "Lead SOC Analyst"
        sarah.department = "Cybersecurity SOC"
        sarah.clearance_level = "Top Secret"
        db.commit()
    else:
        sarah = User(
            id=str(uuid.uuid4()),
            username="sarah.connor",
            email="sarah.connor@apexshield.corp",
            full_name="Sarah Connor",
            department="Cybersecurity SOC",
            role="Lead SOC Analyst",
            clearance_level="Top Secret",
            password_hash=hash_password("Password123!"),
            is_active=True,
            is_locked=False
        )
        db.add(sarah)
        db.commit()

    # Check if Alex Mercer exists
    alex = db.query(User).filter(User.username == "alex.mercer").first()
    if alex:
        alex.role = "Senior SOC Specialist"
        alex.department = "Cybersecurity SOC"
        alex.clearance_level = "Secret"
        db.commit()
    else:
        alex = User(
            id=str(uuid.uuid4()),
            username="alex.mercer",
            email="alex.mercer@apexshield.corp",
            full_name="Alex Mercer",
            department="Cybersecurity SOC",
            role="Senior SOC Specialist",
            clearance_level="Secret",
            password_hash=hash_password("Password123!"),
            is_active=True,
            is_locked=False
        )
        db.add(alex)
        db.commit()

    # Ensure john.doe is regular employee
    john = db.query(User).filter(User.username == "john.doe").first()
    if john:
        john.department = "Engineering"
        john.role = "Senior Software Engineer"
        john.clearance_level = "Confidential"
        db.commit()

    print("[+] Database verified with Admin and SOC co-workers.")
    db.close()

if __name__ == "__main__":
    seed_database()

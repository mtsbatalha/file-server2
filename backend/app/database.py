"""
Database Configuration
SQLAlchemy setup with support for SQLite, PostgreSQL and MySQL
"""

import os
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

from .models.base import Base


def get_database_config():
    """
    Get database configuration from environment variables.
    Supports: SQLite, PostgreSQL, MySQL (local and remote)
    """
    database_url = os.getenv("DATABASE_URL", "sqlite:///./fileserver.db")
    
    # MySQL configuration from individual env vars (for remote MySQL)
    mysql_host = os.getenv("MYSQL_HOST")
    mysql_port = os.getenv("MYSQL_PORT", "3306")
    mysql_user = os.getenv("MYSQL_USER")
    mysql_password = os.getenv("MYSQL_PASSWORD")
    mysql_database = os.getenv("MYSQL_DATABASE")
    
    # If MySQL env vars are set, build the connection URL
    if mysql_host and mysql_user and mysql_password and mysql_database:
        database_url = f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}?charset=utf8mb4"
    
    return database_url


# Database URL from environment
DATABASE_URL = get_database_config()

# Engine configuration based on database type
if DATABASE_URL.startswith("sqlite"):
    # SQLite configuration
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=os.getenv("SQL_ECHO", "false").lower() == "true"
    )
    
    # Enable foreign keys for SQLite
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

elif DATABASE_URL.startswith("mysql"):
    # MySQL configuration (local or remote)
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,  # Recycle connections after 1 hour
        echo=os.getenv("SQL_ECHO", "false").lower() == "true"
    )
    
    # Set MySQL-specific session options
    @event.listens_for(engine, "connect")
    def set_mysql_options(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION'")
        cursor.execute("SET SESSION character_set_connection=utf8mb4")
        cursor.execute("SET SESSION character_set_client=utf8mb4")
        cursor.execute("SET SESSION character_set_results=utf8mb4")
        cursor.close()

else:
    # PostgreSQL configuration
    engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=os.getenv("SQL_ECHO", "false").lower() == "true"
    )

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for getting database sessions.
    Usage:
        @app.get("/")
        async def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Initialize the database.
    Creates all tables if they don't exist.
    """
    from .models import (
        Base, User, Role, Permission,
        Service, ServiceStatus, ServiceType,
        Share, ShareType, SharePermission,
        SystemConfig, BackupConfig, BackupRecord,
        AuditLog, LoginLog, ServiceLog, BlockedIP
    )
    
    Base.metadata.create_all(bind=engine)


def seed_db() -> None:
    """
    Seed the database with initial data.
    Creates default roles, permissions, and admin user.
    """
    from .models.user import User, Role, Permission
    from .models.config import SystemConfig, ConfigType, DEFAULT_CONFIGS
    
    db = SessionLocal()
    
    try:
        # Check if already seeded
        if db.query(User).count() > 0:
            return
        
        # Create default permissions
        permissions_data = [
            # User permissions
            ("users:create", "Create users", "users", "create"),
            ("users:read", "View users", "users", "read"),
            ("users:update", "Update users", "users", "update"),
            ("users:delete", "Delete users", "users", "delete"),
            ("users:list", "List users", "users", "list"),
            
            # Service permissions
            ("services:install", "Install services", "services", "install"),
            ("services:uninstall", "Uninstall services", "services", "uninstall"),
            ("services:start", "Start services", "services", "start"),
            ("services:stop", "Stop services", "services", "stop"),
            ("services:config", "Configure services", "services", "config"),
            ("services:list", "List services", "services", "list"),
            
            # Share permissions
            ("shares:create", "Create shares", "shares", "create"),
            ("shares:read", "View shares", "shares", "read"),
            ("shares:update", "Update shares", "shares", "update"),
            ("shares:delete", "Delete shares", "shares", "delete"),
            ("shares:list", "List shares", "shares", "list"),
            
            # Config permissions
            ("config:read", "View configuration", "config", "read"),
            ("config:update", "Update configuration", "config", "update"),
            
            # Backup permissions
            ("backup:create", "Create backups", "backup", "create"),
            ("backup:restore", "Restore backups", "backup", "restore"),
            ("backup:list", "List backups", "backup", "list"),
            
            # Audit & Logs
            ("audit:read", "View audit logs", "audit", "read"),
            ("logs:read", "View system logs", "logs", "read"),
            
            # Security
            ("security:manage", "Manage security settings", "security", "manage"),
            ("firewall:manage", "Manage firewall", "firewall", "manage"),
        ]
        
        permissions = {}
        for name, desc, resource, action in permissions_data:
            perm = Permission(name=name, description=desc, resource=resource, action=action)
            db.add(perm)
            permissions[name] = perm
        
        db.commit()
        
        # Create default roles
        admin_role = Role(name="admin", description="Administrator with full access", is_system=True)
        operator_role = Role(name="operator", description="Operator with service management", is_system=True)
        auditor_role = Role(name="auditor", description="Read-only auditor access", is_system=True)
        
        # Assign all permissions to admin
        for perm in permissions.values():
            admin_role.permissions.append(perm)
        
        # Assign operator permissions
        operator_perms = [
            "services:start", "services:stop", "services:list", "services:config",
            "shares:create", "shares:read", "shares:update", "shares:delete", "shares:list",
            "users:read", "users:list",
            "backup:create", "backup:list",
            "logs:read"
        ]
        for perm_name in operator_perms:
            if perm_name in permissions:
                operator_role.permissions.append(permissions[perm_name])
        
        # Assign auditor permissions
        auditor_perms = [
            "users:list", "users:read",
            "services:list",
            "shares:list", "shares:read",
            "audit:read", "logs:read",
            "config:read", "backup:list"
        ]
        for perm_name in auditor_perms:
            if perm_name in permissions:
                auditor_role.permissions.append(permissions[perm_name])
        
        db.add(admin_role)
        db.add(operator_role)
        db.add(auditor_role)
        db.commit()
        
        # Create default admin user
        admin_user = User(
            username="admin",
            email="admin@localhost",
            full_name="System Administrator",
            is_active=True,
            is_superuser=True
        )
        admin_user.password = "admin123"  # Will be hashed
        admin_user.roles.append(admin_role)
        
        db.add(admin_user)
        
        # Create default system configuration
        for config_data in DEFAULT_CONFIGS:
            config = SystemConfig(
                key=config_data["key"],
                value=config_data["value"],
                category=config_data["category"],
                description=config_data["description"]
            )
            db.add(config)
        
        db.commit()
        
        print("Database seeded successfully!")
        print("Default admin user: admin / admin123")
        print("Please change the admin password after first login!")
        
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        db.close()


def test_connection() -> bool:
    """
    Test database connection.
    Returns True if connection is successful, False otherwise.
    """
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False
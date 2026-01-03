"""
Core User and Authentication Models using MongoEngine

This module contains the core user and authentication models for the IMFMS backend.
It uses MongoEngine as the ODM (Object-Document Mapper) for MongoDB.

Date Created: 2026-01-03 10:09:06 UTC
"""

from datetime import datetime
from typing import Optional, List
from enum import Enum

from mongoengine import (
    Document,
    StringField,
    EmailField,
    BooleanField,
    DateTimeField,
    ListField,
    ReferenceField,
    EmbeddedDocument,
    EmbeddedDocumentField,
    URLField,
    IntField,
)
from werkzeug.security import generate_password_hash, check_password_hash


class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    MANAGER = "manager"
    STAFF = "staff"
    USER = "user"
    GUEST = "guest"


class UserStatus(str, Enum):
    """User account status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"
    DELETED = "deleted"


class Permission(EmbeddedDocument):
    """Permission embedded document."""
    name = StringField(required=True, unique=True)
    description = StringField()
    resource = StringField(required=True)
    action = StringField(required=True)  # create, read, update, delete
    created_at = DateTimeField(default=datetime.utcnow)

    meta = {
        'collection': 'permissions',
        'strict': False
    }

    def __str__(self):
        return f"{self.resource}:{self.action}"


class UserProfile(EmbeddedDocument):
    """User profile embedded document."""
    first_name = StringField(required=True)
    last_name = StringField(required=True)
    phone_number = StringField()
    avatar_url = URLField()
    bio = StringField()
    department = StringField()
    location = StringField()
    timezone = StringField(default="UTC")
    preferred_language = StringField(default="en")
    updated_at = DateTimeField(default=datetime.utcnow)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class User(Document):
    """
    Core User model for authentication and user management.
    
    This model stores user account information, authentication credentials,
    profile details, and access control information.
    """
    
    # Authentication fields
    email = EmailField(required=True, unique=True, sparse=True)
    username = StringField(required=True, unique=True, sparse=True, min_length=3, max_length=50)
    password_hash = StringField(required=True)
    
    # User profile
    profile = EmbeddedDocumentField(UserProfile, required=True)
    
    # Access control
    role = StringField(
        choices=[role.value for role in UserRole],
        default=UserRole.USER.value
    )
    roles = ListField(StringField(choices=[role.value for role in UserRole]))
    permissions = ListField(EmbeddedDocumentField(Permission))
    
    # Account status
    status = StringField(
        choices=[status.value for status in UserStatus],
        default=UserStatus.PENDING_VERIFICATION.value
    )
    is_active = BooleanField(default=True)
    is_verified = BooleanField(default=False)
    is_two_factor_enabled = BooleanField(default=False)
    
    # Account verification
    email_verified_at = DateTimeField()
    verification_token = StringField()
    verification_token_expires_at = DateTimeField()
    
    # Security
    last_login_at = DateTimeField()
    last_password_changed_at = DateTimeField(default=datetime.utcnow)
    failed_login_attempts = IntField(default=0)
    locked_until = DateTimeField()
    
    # Timestamps
    created_at = DateTimeField(default=datetime.utcnow)
    updated_at = DateTimeField(default=datetime.utcnow)
    deleted_at = DateTimeField()
    
    # Audit fields
    created_by = StringField()
    updated_by = StringField()
    
    # Metadata
    metadata = StringField()  # JSON string or additional data
    
    meta = {
        'collection': 'users',
        'indexes': [
            'email',
            'username',
            'created_at',
            'status',
            'is_active',
            ('email', 'is_active'),
            ('username', 'is_active'),
        ],
        'strict': False
    }
    
    def set_password(self, password: str) -> None:
        """
        Hash and set the user's password.
        
        Args:
            password: The plaintext password to hash
        """
        self.password_hash = generate_password_hash(password)
        self.last_password_changed_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        """
        Verify a plaintext password against the stored hash.
        
        Args:
            password: The plaintext password to verify
            
        Returns:
            True if password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)
    
    def add_permission(self, permission: Permission) -> None:
        """
        Add a permission to the user.
        
        Args:
            permission: The Permission object to add
        """
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission: Permission) -> None:
        """
        Remove a permission from the user.
        
        Args:
            permission: The Permission object to remove
        """
        if permission in self.permissions:
            self.permissions.remove(permission)
    
    def has_permission(self, resource: str, action: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            resource: The resource name
            action: The action to perform
            
        Returns:
            True if user has permission, False otherwise
        """
        if self.role == UserRole.ADMIN.value:
            return True
        
        return any(
            perm.resource == resource and perm.action == action
            for perm in self.permissions
        )
    
    def has_role(self, role: str) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            role: The role to check
            
        Returns:
            True if user has role, False otherwise
        """
        return role in (self.roles or []) or self.role == role
    
    def add_role(self, role: str) -> None:
        """
        Add a role to the user.
        
        Args:
            role: The role to add
        """
        if role not in self.roles:
            if not self.roles:
                self.roles = []
            self.roles.append(role)
    
    def remove_role(self, role: str) -> None:
        """
        Remove a role from the user.
        
        Args:
            role: The role to remove
        """
        if self.roles and role in self.roles:
            self.roles.remove(role)
    
    def lock_account(self, minutes: int = 15) -> None:
        """
        Lock the user account temporarily.
        
        Args:
            minutes: Number of minutes to lock account
        """
        from datetime import timedelta
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        self.failed_login_attempts += 1
    
    def unlock_account(self) -> None:
        """Unlock the user account."""
        self.locked_until = None
        self.failed_login_attempts = 0
    
    def is_account_locked(self) -> bool:
        """
        Check if the user account is locked.
        
        Returns:
            True if account is locked and lock hasn't expired
        """
        if self.locked_until:
            return self.locked_until > datetime.utcnow()
        return False
    
    def record_login(self) -> None:
        """Record the user's login timestamp and reset failed attempts."""
        self.last_login_at = datetime.utcnow()
        self.failed_login_attempts = 0
        self.locked_until = None
    
    def soft_delete(self) -> None:
        """Soft delete the user by setting deleted_at timestamp."""
        self.deleted_at = datetime.utcnow()
        self.is_active = False
        self.status = UserStatus.DELETED.value
    
    def restore(self) -> None:
        """Restore a soft-deleted user."""
        self.deleted_at = None
        self.is_active = True
        self.status = UserStatus.ACTIVE.value
    
    def to_dict(self, include_password: bool = False) -> dict:
        """
        Convert user to dictionary representation.
        
        Args:
            include_password: Whether to include password hash in output
            
        Returns:
            Dictionary representation of the user
        """
        data = {
            'id': str(self.id),
            'email': self.email,
            'username': self.username,
            'profile': {
                'first_name': self.profile.first_name,
                'last_name': self.profile.last_name,
                'phone_number': self.profile.phone_number,
                'avatar_url': self.profile.avatar_url,
                'bio': self.profile.bio,
                'department': self.profile.department,
                'location': self.profile.location,
                'timezone': self.profile.timezone,
                'preferred_language': self.profile.preferred_language,
            },
            'role': self.role,
            'roles': self.roles or [],
            'status': self.status,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'is_two_factor_enabled': self.is_two_factor_enabled,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
        
        if include_password:
            data['password_hash'] = self.password_hash
        
        return data
    
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class AuditLog(Document):
    """
    Audit log model for tracking user actions and system changes.
    
    Stores information about who did what, when, and from where.
    """
    
    user = ReferenceField(User, required=True)
    action = StringField(required=True)
    resource = StringField(required=True)
    resource_id = StringField()
    changes = StringField()  # JSON string of changes
    ip_address = StringField()
    user_agent = StringField()
    status = StringField(default="success")  # success, failure
    error_message = StringField()
    
    created_at = DateTimeField(default=datetime.utcnow)
    
    meta = {
        'collection': 'audit_logs',
        'indexes': [
            'user',
            'action',
            'resource',
            'created_at',
            ('user', 'created_at'),
            ('action', 'created_at'),
        ],
        'strict': False
    }
    
    def __str__(self):
        return f"{self.user.username} - {self.action} on {self.resource}"
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, user='{self.user.username}', action='{self.action}')>"


class LoginSession(Document):
    """
    Login session model for managing user sessions.
    
    Tracks active sessions and provides session management capabilities.
    """
    
    user = ReferenceField(User, required=True)
    token = StringField(required=True, unique=True)
    refresh_token = StringField(unique=True)
    ip_address = StringField()
    user_agent = StringField()
    device_name = StringField()
    
    created_at = DateTimeField(default=datetime.utcnow)
    expires_at = DateTimeField(required=True)
    refresh_expires_at = DateTimeField()
    last_activity_at = DateTimeField(default=datetime.utcnow)
    
    is_active = BooleanField(default=True)
    
    meta = {
        'collection': 'login_sessions',
        'indexes': [
            'user',
            'token',
            'refresh_token',
            'created_at',
            'expires_at',
            'is_active',
            ('user', 'is_active'),
            ('token', 'is_active'),
        ],
        'strict': False
    }
    
    def is_expired(self) -> bool:
        """
        Check if the session has expired.
        
        Returns:
            True if session has expired
        """
        return self.expires_at < datetime.utcnow()
    
    def is_refresh_expired(self) -> bool:
        """
        Check if the refresh token has expired.
        
        Returns:
            True if refresh token has expired
        """
        if not self.refresh_expires_at:
            return False
        return self.refresh_expires_at < datetime.utcnow()
    
    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity_at = datetime.utcnow()
    
    def invalidate(self) -> None:
        """Invalidate the session."""
        self.is_active = False
    
    def __str__(self):
        return f"Session for {self.user.username}"
    
    def __repr__(self):
        return f"<LoginSession(id={self.id}, user='{self.user.username}', token='{self.token[:20]}...')>"

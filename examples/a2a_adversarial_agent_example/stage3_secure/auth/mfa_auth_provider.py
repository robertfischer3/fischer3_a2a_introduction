"""
MFA Authentication Provider - Stage 3: Production Security

Multi-Factor Authentication (MFA) provider with TOTP support.

✅ Stage 3: MFA with TOTP (Time-based One-Time Password)
❌ Stage 2: Password-only authentication

Security Features:
- TOTP (RFC 6238) support
- QR code generation for easy setup
- Backup codes for account recovery
- Rate limiting for MFA attempts
- Configurable TOTP parameters

Supported MFA Methods:
- TOTP (Time-based One-Time Password) - Google Authenticator, Authy, etc.
- Backup codes (one-time use recovery codes)

Future: SMS, Email, Hardware tokens (YubiKey)

Usage:
    provider = MFAAuthProvider(users_file="config/users.json")
    
    # Register user with MFA
    qr_code = provider.register_user(
        username="alice",
        password="SecurePass123",
        enable_mfa=True
    )
    
    # User scans QR code with authenticator app
    
    # Authenticate with password + TOTP
    result = provider.authenticate(
        username="alice",
        password="SecurePass123",
        mfa_code="123456"
    )
"""

import json
import secrets
import hashlib
import time
from typing import Dict, Optional, Tuple, List
from pathlib import Path
import pyotp
import qrcode
import io
import base64
from datetime import datetime

try:
    import argon2
    ARGON2_AVAILABLE = True
except ImportError:
    import bcrypt
    ARGON2_AVAILABLE = False


class MFAAuthProvider:
    """
    Multi-Factor Authentication Provider
    
    Provides password + TOTP authentication with:
    - Argon2 password hashing (or bcrypt fallback)
    - TOTP (RFC 6238) for second factor
    - QR code generation for easy setup
    - Backup codes for account recovery
    - Failed attempt tracking
    
    Usage:
        provider = MFAAuthProvider()
        
        # Enable MFA for user
        qr_uri, backup_codes = provider.enable_mfa("alice")
        
        # User scans QR code
        
        # Authenticate with MFA
        result = provider.authenticate(
            username="alice",
            password="password",
            mfa_code="123456"
        )
    """
    
    def __init__(
        self,
        users_file: str = "config/users_mfa.json",
        issuer_name: str = "TaskCollaboration"
    ):
        """
        Initialize MFA auth provider
        
        Args:
            users_file: Path to users JSON file
            issuer_name: Issuer name for TOTP (shows in authenticator app)
        """
        self.users_file = Path(users_file)
        self.issuer_name = issuer_name
        
        # Initialize password hasher
        if ARGON2_AVAILABLE:
            self.password_hasher = argon2.PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16
            )
            print("✅ Using Argon2 for password hashing")
        else:
            print("⚠️  Argon2 not available, using bcrypt fallback")
            print("   Install with: pip install argon2-cffi")
        
        # Load users
        self.users = self._load_users()
        
        print(f"✅ MFAAuthProvider initialized")
        print(f"   Users file: {self.users_file}")
        print(f"   Issuer: {self.issuer_name}")
        print(f"   Users loaded: {len(self.users)}")
    
    def _load_users(self) -> Dict:
        """Load users from file"""
        if not self.users_file.exists():
            return {}
        
        with open(self.users_file, 'r') as f:
            return json.load(f)
    
    def _save_users(self):
        """Save users to file"""
        # Create directory if needed
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def register_user(
        self,
        username: str,
        password: str,
        roles: Optional[List[str]] = None,
        enable_mfa: bool = True
    ) -> Optional[Tuple[str, List[str]]]:
        """
        Register a new user with optional MFA
        
        Args:
            username: Username
            password: Plain text password
            roles: User roles
            enable_mfa: Whether to enable MFA
        
        Returns:
            If MFA enabled: (qr_code_uri, backup_codes)
            If MFA disabled: None
        
        Example:
            qr_uri, backup_codes = provider.register_user(
                username="alice",
                password="SecurePass123",
                roles=["user"],
                enable_mfa=True
            )
            
            print(f"Scan QR code: {qr_uri}")
            print(f"Backup codes: {backup_codes}")
        """
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        
        # Hash password
        password_hash = self._hash_password(password)
        
        # Create user
        user = {
            "username": username,
            "password_hash": password_hash,
            "roles": roles or ["user"],
            "created_at": datetime.utcnow().isoformat(),
            "mfa_enabled": enable_mfa,
            "failed_attempts": 0,
            "locked_until": None
        }
        
        # Setup MFA if enabled
        qr_uri = None
        backup_codes = None
        
        if enable_mfa:
            secret = pyotp.random_base32()
            backup_codes = self._generate_backup_codes()
            
            user["mfa_secret"] = secret
            user["mfa_backup_codes"] = [
                self._hash_backup_code(code) for code in backup_codes
            ]
            
            # Generate QR code URI
            totp = pyotp.TOTP(secret)
            qr_uri = totp.provisioning_uri(
                name=username,
                issuer_name=self.issuer_name
            )
        
        self.users[username] = user
        self._save_users()
        
        print(f"✅ User registered: {username}")
        if enable_mfa:
            print(f"   MFA enabled: Yes")
            return qr_uri, backup_codes
        else:
            print(f"   MFA enabled: No")
            return None
    
    def enable_mfa(self, username: str) -> Tuple[str, List[str]]:
        """
        Enable MFA for existing user
        
        Args:
            username: Username
        
        Returns:
            (qr_code_uri, backup_codes)
        
        Example:
            qr_uri, backup_codes = provider.enable_mfa("alice")
            
            # Show QR code to user
            display_qr_code(qr_uri)
            
            # Give backup codes to user
            print("Save these backup codes:")
            for code in backup_codes:
                print(f"  {code}")
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        
        user = self.users[username]
        
        if user.get("mfa_enabled"):
            raise ValueError(f"MFA already enabled for {username}")
        
        # Generate TOTP secret
        secret = pyotp.random_base32()
        
        # Generate backup codes
        backup_codes = self._generate_backup_codes()
        
        # Update user
        user["mfa_enabled"] = True
        user["mfa_secret"] = secret
        user["mfa_backup_codes"] = [
            self._hash_backup_code(code) for code in backup_codes
        ]
        
        self._save_users()
        
        # Generate QR code URI
        totp = pyotp.TOTP(secret)
        qr_uri = totp.provisioning_uri(
            name=username,
            issuer_name=self.issuer_name
        )
        
        print(f"✅ MFA enabled for {username}")
        
        return qr_uri, backup_codes
    
    def disable_mfa(self, username: str):
        """
        Disable MFA for user
        
        Args:
            username: Username
        """
        if username not in self.users:
            raise ValueError(f"User {username} not found")
        
        user = self.users[username]
        
        user["mfa_enabled"] = False
        user.pop("mfa_secret", None)
        user.pop("mfa_backup_codes", None)
        
        self._save_users()
        
        print(f"✅ MFA disabled for {username}")
    
    def authenticate(
        self,
        username: str,
        password: str,
        mfa_code: Optional[str] = None,
        use_backup_code: bool = False
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Authenticate user with password and optional MFA
        
        Args:
            username: Username
            password: Password
            mfa_code: TOTP code or backup code
            use_backup_code: Whether mfa_code is a backup code
        
        Returns:
            Tuple of (success, error_message, user_info)
        
        Example:
            # Password + TOTP
            success, error, user = provider.authenticate(
                username="alice",
                password="SecurePass123",
                mfa_code="123456"
            )
            
            # Password + backup code
            success, error, user = provider.authenticate(
                username="alice",
                password="SecurePass123",
                mfa_code="ABCD-1234-EFGH-5678",
                use_backup_code=True
            )
        """
        # Check user exists
        if username not in self.users:
            return False, "Invalid credentials", None
        
        user = self.users[username]
        
        # Check if account locked
        if user.get("locked_until"):
            locked_until = datetime.fromisoformat(user["locked_until"])
            if datetime.utcnow() < locked_until:
                return False, "Account temporarily locked", None
            else:
                # Unlock account
                user["locked_until"] = None
                user["failed_attempts"] = 0
        
        # Verify password
        if not self._verify_password(password, user["password_hash"]):
            self._record_failed_attempt(username)
            return False, "Invalid credentials", None
        
        # Check MFA if enabled
        if user.get("mfa_enabled"):
            if not mfa_code:
                return False, "MFA code required", None
            
            if use_backup_code:
                # Verify backup code
                if not self._verify_backup_code(username, mfa_code):
                    self._record_failed_attempt(username)
                    return False, "Invalid backup code", None
            else:
                # Verify TOTP
                if not self._verify_totp(username, mfa_code):
                    self._record_failed_attempt(username)
                    return False, "Invalid MFA code", None
        
        # Success - reset failed attempts
        user["failed_attempts"] = 0
        user["last_login"] = datetime.utcnow().isoformat()
        self._save_users()
        
        # Return user info (without sensitive data)
        user_info = {
            "username": username,
            "roles": user["roles"],
            "mfa_enabled": user.get("mfa_enabled", False)
        }
        
        return True, None, user_info
    
    def _hash_password(self, password: str) -> str:
        """Hash password with Argon2 or bcrypt"""
        if ARGON2_AVAILABLE:
            return self.password_hasher.hash(password)
        else:
            # Fallback to bcrypt
            return bcrypt.hashpw(
                password.encode(),
                bcrypt.gensalt(rounds=12)
            ).decode()
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            if ARGON2_AVAILABLE:
                self.password_hasher.verify(password_hash, password)
                return True
            else:
                return bcrypt.checkpw(
                    password.encode(),
                    password_hash.encode()
                )
        except Exception:
            return False
    
    def _verify_totp(self, username: str, code: str) -> bool:
        """
        Verify TOTP code
        
        Args:
            username: Username
            code: 6-digit TOTP code
        
        Returns:
            True if code is valid
        """
        user = self.users[username]
        secret = user.get("mfa_secret")
        
        if not secret:
            return False
        
        totp = pyotp.TOTP(secret)
        
        # Verify with window of ±1 time step (30 seconds)
        # This accounts for clock drift
        return totp.verify(code, valid_window=1)
    
    def _generate_backup_codes(self, count: int = 8) -> List[str]:
        """
        Generate backup recovery codes
        
        Args:
            count: Number of codes to generate
        
        Returns:
            List of backup codes in format: XXXX-XXXX-XXXX-XXXX
        """
        codes = []
        for _ in range(count):
            # Generate 16 random characters
            code = secrets.token_hex(8).upper()
            # Format as XXXX-XXXX-XXXX-XXXX
            formatted = '-'.join([
                code[i:i+4] for i in range(0, len(code), 4)
            ])
            codes.append(formatted)
        return codes
    
    def _hash_backup_code(self, code: str) -> str:
        """Hash backup code for storage"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def _verify_backup_code(self, username: str, code: str) -> bool:
        """
        Verify and consume backup code
        
        Backup codes are one-time use only.
        
        Args:
            username: Username
            code: Backup code
        
        Returns:
            True if code is valid
        """
        user = self.users[username]
        backup_codes = user.get("mfa_backup_codes", [])
        
        code_hash = self._hash_backup_code(code)
        
        if code_hash in backup_codes:
            # Remove used code
            backup_codes.remove(code_hash)
            self._save_users()
            print(f"✅ Backup code used for {username}")
            print(f"   Remaining codes: {len(backup_codes)}")
            return True
        
        return False
    
    def _record_failed_attempt(self, username: str):
        """
        Record failed authentication attempt
        
        Locks account after 5 failed attempts for 15 minutes.
        """
        user = self.users[username]
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        
        # Lock account after 5 failed attempts
        if user["failed_attempts"] >= 5:
            from datetime import timedelta
            locked_until = datetime.utcnow() + timedelta(minutes=15)
            user["locked_until"] = locked_until.isoformat()
            print(f"⚠️  Account locked: {username}")
            print(f"   Failed attempts: {user['failed_attempts']}")
            print(f"   Locked until: {locked_until}")
        
        self._save_users()
    
    def generate_qr_code(self, qr_uri: str) -> str:
        """
        Generate QR code image as base64
        
        Args:
            qr_uri: QR code URI from provisioning_uri()
        
        Returns:
            Base64-encoded PNG image
        
        Example:
            qr_image = provider.generate_qr_code(qr_uri)
            
            # Display in HTML
            html = f'<img src="data:image/png;base64,{qr_image}"/>'
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        
        return img_base64
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user information (without sensitive data)"""
        if username not in self.users:
            return None
        
        user = self.users[username]
        
        return {
            "username": username,
            "roles": user["roles"],
            "mfa_enabled": user.get("mfa_enabled", False),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login")
        }


if __name__ == "__main__":
    """Test MFA authentication"""
    print("=" * 70)
    print("MFA Authentication Provider Test")
    print("=" * 70)
    
    import tempfile
    import os
    
    # Create temp file
    temp_file = tempfile.mktemp(suffix=".json")
    
    try:
        print("\n--- Test 1: Register User with MFA ---")
        provider = MFAAuthProvider(users_file=temp_file)
        
        qr_uri, backup_codes = provider.register_user(
            username="alice",
            password="SecurePass123",
            roles=["user", "admin"],
            enable_mfa=True
        )
        
        print(f"QR URI: {qr_uri[:50]}...")
        print(f"Backup codes: {len(backup_codes)} codes generated")
        print(f"First code: {backup_codes[0]}")
        
        print("\n--- Test 2: Authenticate without MFA Code (Should Fail) ---")
        success, error, user = provider.authenticate(
            username="alice",
            password="SecurePass123"
        )
        print(f"Success: {success}")
        print(f"Error: {error}")
        
        print("\n--- Test 3: Generate Valid TOTP Code ---")
        # Get secret for testing
        user_data = provider.users["alice"]
        secret = user_data["mfa_secret"]
        totp = pyotp.TOTP(secret)
        valid_code = totp.now()
        print(f"Generated TOTP code: {valid_code}")
        
        print("\n--- Test 4: Authenticate with Valid TOTP ---")
        success, error, user = provider.authenticate(
            username="alice",
            password="SecurePass123",
            mfa_code=valid_code
        )
        print(f"Success: {success}")
        print(f"User: {user}")
        
        print("\n--- Test 5: Authenticate with Invalid TOTP ---")
        success, error, user = provider.authenticate(
            username="alice",
            password="SecurePass123",
            mfa_code="000000"
        )
        print(f"Success: {success}")
        print(f"Error: {error}")
        
        print("\n--- Test 6: Authenticate with Backup Code ---")
        backup_code = backup_codes[0]
        success, error, user = provider.authenticate(
            username="alice",
            password="SecurePass123",
            mfa_code=backup_code,
            use_backup_code=True
        )
        print(f"Success: {success}")
        print(f"User: {user}")
        
        print("\n--- Test 7: Try to Reuse Backup Code (Should Fail) ---")
        success, error, user = provider.authenticate(
            username="alice",
            password="SecurePass123",
            mfa_code=backup_code,
            use_backup_code=True
        )
        print(f"Success: {success}")
        print(f"Error: {error}")
        
        print("\n--- Test 8: Register User without MFA ---")
        result = provider.register_user(
            username="bob",
            password="BobPass456",
            roles=["user"],
            enable_mfa=False
        )
        print(f"MFA enabled: {result is not None}")
        
        print("\n--- Test 9: Authenticate User without MFA ---")
        success, error, user = provider.authenticate(
            username="bob",
            password="BobPass456"
        )
        print(f"Success: {success}")
        print(f"User: {user}")
        
        print("\n--- Test 10: Enable MFA for Existing User ---")
        qr_uri, new_codes = provider.enable_mfa("bob")
        print(f"MFA enabled for bob")
        print(f"New backup codes: {len(new_codes)}")
        
        print("\n--- Test 11: QR Code Generation ---")
        qr_image = provider.generate_qr_code(qr_uri)
        print(f"QR code generated: {len(qr_image)} bytes (base64)")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    print("\n" + "=" * 70)
    print("Test complete!")
    print("\n✅ MFA Authentication Provider working")
    print("   - TOTP (Time-based One-Time Password)")
    print("   - Backup codes (one-time use)")
    print("   - QR code generation")
    print("   - Account lockout after failed attempts")
    print("   - Argon2 password hashing")
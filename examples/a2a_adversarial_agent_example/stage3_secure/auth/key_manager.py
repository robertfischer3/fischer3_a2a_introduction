"""
Key Manager - Stage 3

RSA keypair management for JWT RS256 signing

Provides asymmetric cryptography for JWT tokens, replacing Stage 2's
symmetric HS256 signing.

Stage 2 Problem:
    HS256 uses shared secret - anyone with secret can create tokens.
    Key must be distributed to all agents (security risk).

Stage 3 Solution:
    - RS256 with RSA 2048-bit keypairs
    - Private key stays on server (never distributed)
    - Public key can be safely shared for verification
    - Key rotation support
    - Secure storage
"""

import os
import secrets
from typing import Tuple, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import jwt


class KeyManager:
    """
    Manages RSA keypairs for JWT RS256 signing
    
    Features:
    - RSA 2048-bit key generation
    - PEM format storage
    - Key rotation
    - JWT signing/verification with RS256
    """
    
    def __init__(self, private_key_path: Optional[str] = None,
                 public_key_path: Optional[str] = None):
        """
        Initialize key manager
        
        Args:
            private_key_path: Path to private key file (creates if not exists)
            public_key_path: Path to public key file (creates if not exists)
        """
        self.private_key_path = private_key_path or "private_key.pem"
        self.public_key_path = public_key_path or "public_key.pem"
        
        self.private_key = None
        self.public_key = None
        
        # Load or generate keys
        self._initialize_keys()
    
    def _initialize_keys(self):
        """Load existing keys or generate new ones"""
        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            # Load existing keys
            self.load_keys()
        else:
            # Generate new keypair
            self.generate_keypair()
    
    def generate_keypair(self, key_size: int = 2048) -> Tuple[bytes, bytes]:
        """
        Generate new RSA keypair
        
        Args:
            key_size: RSA key size in bits (2048 recommended minimum)
            
        Returns:
            (private_key_pem, public_key_pem)
        """
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Derive public key
        self.public_key = self.private_key.public_key()
        
        # Serialize to PEM format
        private_pem = self._serialize_private_key(self.private_key)
        public_pem = self._serialize_public_key(self.public_key)
        
        # Save to disk
        self._save_private_key(private_pem)
        self._save_public_key(public_pem)
        
        return private_pem, public_pem
    
    def load_keys(self):
        """Load keys from disk"""
        # Load private key
        with open(self.private_key_path, 'rb') as f:
            private_pem = f.read()
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,  # Use password in production!
                backend=default_backend()
            )
        
        # Load public key
        with open(self.public_key_path, 'rb') as f:
            public_pem = f.read()
            self.public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
    
    def create_jwt_token(self, payload: dict, expires_in: int = 3600) -> str:
        """
        Create JWT token signed with RS256
        
        Args:
            payload: Token payload (claims)
            expires_in: Expiration time in seconds
            
        Returns:
            JWT token string
        """
        # Add standard claims
        now = datetime.utcnow()
        payload_with_claims = {
            **payload,
            'iat': now,  # Issued at
            'exp': now + timedelta(seconds=expires_in),  # Expires
            'jti': secrets.token_hex(16)  # JWT ID (unique identifier)
        }
        
        # Sign with private key using RS256
        private_pem = self._serialize_private_key(self.private_key)
        
        token = jwt.encode(
            payload_with_claims,
            private_pem,
            algorithm='RS256'
        )
        
        return token
    
    def verify_jwt_token(self, token: str) -> Tuple[bool, Optional[dict], str]:
        """
        Verify JWT token with public key
        
        Args:
            token: JWT token to verify
            
        Returns:
            (is_valid, payload, error_message)
        """
        try:
            public_pem = self._serialize_public_key(self.public_key)
            
            payload = jwt.decode(
                token,
                public_pem,
                algorithms=['RS256']
            )
            
            return True, payload, "Token valid"
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            return False, None, f"Invalid token: {str(e)}"
    
    def rotate_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate new keypair and archive old one
        
        Returns:
            (new_private_pem, new_public_pem)
        """
        # Archive old keys
        if os.path.exists(self.private_key_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_private = f"{self.private_key_path}.{timestamp}.bak"
            archive_public = f"{self.public_key_path}.{timestamp}.bak"
            
            os.rename(self.private_key_path, archive_private)
            os.rename(self.public_key_path, archive_public)
        
        # Generate new keys
        return self.generate_keypair()
    
    def get_public_key_pem(self) -> bytes:
        """Get public key in PEM format (safe to distribute)"""
        return self._serialize_public_key(self.public_key)
    
    def _serialize_private_key(self, private_key) -> bytes:
        """Serialize private key to PEM format"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Use password in production!
        )
    
    def _serialize_public_key(self, public_key) -> bytes:
        """Serialize public key to PEM format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def _save_private_key(self, private_pem: bytes):
        """Save private key to disk with restricted permissions"""
        with open(self.private_key_path, 'wb') as f:
            f.write(private_pem)
        
        # Set restrictive permissions (owner read/write only)
        os.chmod(self.private_key_path, 0o600)
    
    def _save_public_key(self, public_pem: bytes):
        """Save public key to disk"""
        with open(self.public_key_path, 'wb') as f:
            f.write(public_pem)
    
    def sign_data(self, data: bytes) -> bytes:
        """
        Sign arbitrary data with private key
        
        Args:
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Verify signature with public key
        
        Args:
            data: Original data
            signature: Signature to verify
            
        Returns:
            True if valid, False otherwise
        """
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    import shutil
    
    print("=" * 70)
    print("KEY MANAGER - RSA KEYPAIR & JWT RS256")
    print("=" * 70)
    print()
    
    # Create temporary directory for keys
    temp_dir = tempfile.mkdtemp()
    private_path = os.path.join(temp_dir, "test_private.pem")
    public_path = os.path.join(temp_dir, "test_public.pem")
    
    try:
        # Test 1: Generate keypair
        print("Test 1: Generating RSA 2048-bit keypair")
        km = KeyManager(private_path, public_path)
        
        print(f"  Private key saved: {private_path}")
        print(f"  Public key saved: {public_path}")
        print(f"  Key size: 2048 bits")
        print()
        
        # Test 2: Create JWT token
        print("Test 2: Creating JWT token with RS256")
        payload = {
            "agent_id": "worker-001",
            "role": "worker",
            "permissions": ["READ_OWN_TASKS", "UPDATE_OWN_TASKS"]
        }
        
        token = km.create_jwt_token(payload, expires_in=3600)
        print(f"  Payload: {payload}")
        print(f"  Token: {token[:50]}...")
        print(f"  Algorithm: RS256 (asymmetric)")
        print()
        
        # Test 3: Verify valid token
        print("Test 3: Verifying valid token")
        is_valid, decoded, message = km.verify_jwt_token(token)
        
        print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print(f"  Message: {message}")
        if decoded:
            print(f"  Agent ID: {decoded.get('agent_id')}")
            print(f"  Role: {decoded.get('role')}")
            print(f"  Expires: {datetime.fromtimestamp(decoded['exp'])}")
        print()
        
        # Test 4: Tampered token (should fail)
        print("Test 4: Detecting tampered token")
        tampered_token = token[:-10] + "TAMPERED!!"
        
        is_valid, decoded, message = km.verify_jwt_token(tampered_token)
        print(f"  Result: {'✅ VALID' if is_valid else '❌ INVALID (correctly detected)'}")
        print(f"  Message: {message}")
        print()
        
        # Test 5: Sign and verify data
        print("Test 5: Signing arbitrary data")
        data = b"Important message to sign"
        signature = km.sign_data(data)
        
        print(f"  Data: {data.decode()}")
        print(f"  Signature: {signature.hex()[:32]}...")
        print()
        
        is_valid = km.verify_signature(data, signature)
        print(f"  Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")
        print()
        
        # Test 6: Detect tampered data
        print("Test 6: Detecting tampered data")
        tampered_data = b"Important message to sign - TAMPERED"
        
        is_valid = km.verify_signature(tampered_data, signature)
        print(f"  Tampered data: {tampered_data.decode()}")
        print(f"  Verification: {'✅ VALID' if is_valid else '❌ INVALID (correctly detected)'}")
        print()
        
        # Test 7: Key rotation
        print("Test 7: Key rotation")
        print("  Generating new keypair...")
        
        old_public = km.get_public_key_pem()
        km.rotate_keys()
        new_public = km.get_public_key_pem()
        
        print(f"  Old key archived: {private_path}.*.bak")
        print(f"  New key generated: {private_path}")
        print(f"  Keys different: {old_public != new_public}")
        print()
        
        # Old token won't verify with new key
        is_valid, decoded, message = km.verify_jwt_token(token)
        print(f"  Old token with new key: {'✅ VALID' if is_valid else '❌ INVALID (expected)'}")
        print()
        
        # Test 8: Public key distribution
        print("Test 8: Public key distribution (safe)")
        public_pem = km.get_public_key_pem()
        
        print(f"  Public key PEM (safe to share):")
        print(f"  {public_pem.decode()[:60]}...")
        print()
        print("  ✅ Can distribute to agents for verification")
        print("  ✅ Cannot create tokens with public key")
        print("  ✅ Only server has private key")
        print()
        
    finally:
        # Cleanup
        shutil.rmtree(temp_dir)
        print(f"Cleaned up temporary directory: {temp_dir}")
        print()
    
    print("=" * 70)
    print("🎓 LESSON: Asymmetric cryptography (RS256)")
    print()
    print("   Stage 2 (HS256 - Symmetric):")
    print("     ❌ Shared secret must be distributed")
    print("     ❌ Anyone with secret can create tokens")
    print("     ❌ Key compromise = full system compromise")
    print()
    print("   Stage 3 (RS256 - Asymmetric):")
    print("     ✅ Private key stays on server (never shared)")
    print("     ✅ Public key safely distributed to agents")
    print("     ✅ Only server can create tokens")
    print("     ✅ Agents can verify tokens")
    print("     ✅ Key rotation doesn't require redistribution")
    print()
    print("   Security improvement: SIGNIFICANT")
    print("=" * 70)
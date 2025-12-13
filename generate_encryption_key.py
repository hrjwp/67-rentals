"""
Generate a secure encryption key for DATA_ENCRYPTION_KEY
Run this: python generate_encryption_key.py
"""
import os
import base64

def generate_encryption_key():
    """Generate a secure 32-byte (256-bit) key and encode it as URL-safe base64"""
    # Generate 32 random bytes (256-bit key for AES-256)
    key = os.urandom(32)
    
    # Encode as URL-safe base64
    key_b64 = base64.urlsafe_b64encode(key).decode('utf-8')
    
    print("=" * 60)
    print("ENCRYPTION KEY GENERATED")
    print("=" * 60)
    print(f"\nYour DATA_ENCRYPTION_KEY:")
    print(f"\n{key_b64}\n")
    print("=" * 60)
    print("\nIMPORTANT: Save this key securely! You'll need it to decrypt backups.")
    print("=" * 60)
    print("\nTo set it on Windows PowerShell:")
    print(f'$env:DATA_ENCRYPTION_KEY="{key_b64}"')
    print("\nOr create a .env file with:")
    print(f'DATA_ENCRYPTION_KEY={key_b64}')
    print("\n" + "=" * 60)
    
    return key_b64

if __name__ == "__main__":
    generate_encryption_key()


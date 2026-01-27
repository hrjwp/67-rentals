"""
Simple script to create .env file with encryption key and secret key
Run: py setup_env.py
"""
import os
import secrets

# Your encryption key
ENCRYPTION_KEY = "Rhdn0S0SrzMO6zJIO1nM188kle3_ep6drQBAKjSeuw8="

# Generate a secure secret key for Flask sessions
SECRET_KEY = secrets.token_urlsafe(32)  # 32 bytes = 256-bit key

# Create .env file
env_file = os.path.join(os.path.dirname(__file__), '.env')

# Check if .env exists and read existing values
existing_vars = {}
if os.path.exists(env_file):
    print("✓ .env file already exists")
    with open(env_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                existing_vars[key.strip()] = value.strip()
    
    # Keep existing keys if they exist
    if 'DATA_ENCRYPTION_KEY' in existing_vars:
        ENCRYPTION_KEY = existing_vars['DATA_ENCRYPTION_KEY']
    if 'SECRET_KEY' in existing_vars:
        SECRET_KEY = existing_vars['SECRET_KEY']
        print("✓ Keeping existing SECRET_KEY")
    else:
        print(f"✓ Generated new SECRET_KEY: {SECRET_KEY[:20]}...")
    
    response = input("Update .env file? (y/n): ")
    if response.lower() != 'y':
        print("Cancelled.")
        exit()
else:
    print(f"✓ Generated new SECRET_KEY: {SECRET_KEY[:20]}...")

# Write .env file
with open(env_file, 'w') as f:
    f.write(f"DATA_ENCRYPTION_KEY={ENCRYPTION_KEY}\n")
    f.write(f"SECRET_KEY={SECRET_KEY}\n")

print("=" * 60)
print("✓ .env file created/updated successfully!")
print("=" * 60)
print("\n✓ DATA_ENCRYPTION_KEY configured")
print("✓ SECRET_KEY configured")
print("\nYou can now start Flask normally:")
print("  py app.py")
print("\nBoth keys will be loaded automatically from .env")
print("=" * 60)


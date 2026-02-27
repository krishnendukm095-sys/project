"""
Encryption Key Setup Script for SurakshaSakhi
Generates secure Fernet encryption keys for complaint data protection
"""

from cryptography.fernet import Fernet
import os
import json
from datetime import datetime

def generate_encryption_key():
    """Generate a new Fernet encryption key"""
    return Fernet.generate_key().decode()

def setup_encryption():
    """Set up encryption keys and configuration"""
    print("=" * 60)
    print("SurakshaSakhi - Encryption Setup")
    print("=" * 60)
    print()
    
    # Generate encryption key
    print("Generating secure encryption key...")
    encryption_key = generate_encryption_key()
    
    print("\n✓ Encryption Key Generated Successfully\n")
    print("ENCRYPTION KEY (Save this securely):")
    print("-" * 60)
    print(encryption_key)
    print("-" * 60)
    
    # Create environment configuration
    env_config = {
        "ENCRYPTION_KEY": encryption_key,
        "SETUP_DATE": datetime.now().isoformat(),
        "ALGORITHM": "Fernet (symmetric encryption)",
        "KEY_SIZE": "256-bit"
    }
    
    # Save to .env file
    with open('.env', 'w') as f:
        f.write(f"ENCRYPTION_KEY={encryption_key}\n")
        f.write(f"FLASK_ENV=production\n")
        f.write(f"SECRET_KEY=your_secret_key_here\n")
    
    print("\n✓ Configuration saved to .env file")
    print("\nSetup Instructions:")
    print("1. Copy the ENCRYPTION_KEY above")
    print("2. Add it to your .env file or environment variables")
    print("3. Update the ENCRYPTION_KEY in app.py")
    print("4. Never share this key - keep it secure!")
    print()
    print("IMPORTANT: This key MUST be the same across all instances")
    print("of the application. Store it safely in your deployment!")
    print()

if __name__ == "__main__":
    setup_encryption()

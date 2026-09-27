import os
import sqlite3
import datetime
import hashlib
import json
import base64

class FileManager:
    """
    Centralized File Management System for NexaShield.
    Handles secure vaulting, database registration, and data exports across the app.
    """
    def __init__(self, session_manager):
        self.session = session_manager
        self.vault_dir = os.path.join(self.session.workspace_dir, "vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        self.db_path = self.session.get_db_path()

    def _xor_encrypt_decrypt(self, data: bytes, key: str = "NEXASHIELD_SECURE_KEY") -> bytes:
        """Simple symmetric encryption for vaulting files securely."""
        key_bytes = key.encode('utf-8')
        return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

    def _hash_data(self, data: bytes) -> str:
        """Returns SHA-256 hash of the data for integrity verification."""
        return hashlib.sha256(data).hexdigest()

    def get_all_files(self):
        """Retrieve all files registered in the vault."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, filename, filepath, module_source, file_type, tags, timestamp, file_size, file_hash FROM file_registry ORDER BY id DESC")
        rows = cursor.fetchall()
        conn.close()
        
        files = []
        for r in rows:
            files.append({
                'id': r[0],
                'filename': r[1],
                'filepath': r[2],
                'module_source': r[3],
                'file_type': r[4],
                'tags': r[5],
                'timestamp': r[6],
                'file_size': r[7],
                'file_hash': r[8]
            })
        return files

    def read_file(self, filepath):
        """Reads and decrypts a file from the vault."""
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        return self._xor_encrypt_decrypt(encrypted_data)

    def export_file(self, filename: str, content, module_source: str, file_type: str, tags: str):
        """
        Main entry point for modules to save files.
        1. Encrypts the content
        2. Saves to vault
        3. Registers in DB
        """
        # Ensure content is bytes
        if isinstance(content, str):
            raw_bytes = content.encode('utf-8')
        else:
            raw_bytes = content
            
        file_hash = self._hash_data(raw_bytes)
        encrypted_bytes = self._xor_encrypt_decrypt(raw_bytes)
        file_size = len(raw_bytes)
        
        # Ensure unique filename to prevent overwrites in vault
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp_str}_{filename}"
        filepath = os.path.join(self.vault_dir, safe_filename)
        
        # Save to disk
        with open(filepath, 'wb') as f:
            f.write(encrypted_bytes)
            
        # Register in DB
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO file_registry (filename, filepath, module_source, file_type, tags, timestamp, file_size, file_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (filename, filepath, module_source, file_type, tags, datetime.datetime.now().isoformat(), file_size, file_hash))
        conn.commit()
        conn.close()
        
        return filepath
        
    def delete_file(self, file_id, filepath):
        """Deletes file from disk and database."""
        if os.path.exists(filepath):
            os.remove(filepath)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM file_registry WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()

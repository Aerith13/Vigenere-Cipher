def vigenere_encrypt(plaintext, keyword):
    """
    Encrypts plaintext using the Vigenère cipher with the given keyword.
    
    Args:
        plaintext (str): The message to encrypt
        keyword (str): The encryption key
    
    Returns:
        str: The encrypted ciphertext
    """
    ciphertext = ""
    keyword = keyword.upper()
    plaintext = plaintext.upper()
    key_length = len(keyword)
    
    print("\nEncryption Process:")
    print(f"{'Character':<10} {'Key':<10} {'Shift':<10} {'Result':<10}")
    print("-" * 40)
    
    for i in range(len(plaintext)):
        char = plaintext[i]
        
        # Skip non-alphabetic characters
        if not char.isalpha():
            ciphertext += char
            print(f"{char:<10} {'-':<10} {'-':<10} {char:<10}")
            continue
        
        # Get the shift value from the keyword
        key_char = keyword[i % key_length]
        shift = ord(key_char) - ord('A')
        
        # Apply the shift
        if char.isalpha():
            # Convert to 0-25 range, apply shift, and convert back
            char_code = (ord(char) - ord('A') + shift) % 26
            encrypted_char = chr(char_code + ord('A'))
            ciphertext += encrypted_char
            
            print(f"{char:<10} {key_char:<10} {shift:<10} {encrypted_char:<10}")
    
    return ciphertext

def vigenere_decrypt(ciphertext, keyword):
    """
    Decrypts ciphertext using the Vigenère cipher with the given keyword.
    
    Args:
        ciphertext (str): The encrypted message
        keyword (str): The decryption key
    
    Returns:
        str: The decrypted plaintext
    """
    plaintext = ""
    keyword = keyword.upper()
    ciphertext = ciphertext.upper()
    key_length = len(keyword)
    
    print("\nDecryption Process:")
    print(f"{'Character':<10} {'Key':<10} {'Shift':<10} {'Result':<10}")
    print("-" * 40)
    
    for i in range(len(ciphertext)):
        char = ciphertext[i]
        
        # Skip non-alphabetic characters
        if not char.isalpha():
            plaintext += char
            print(f"{char:<10} {'-':<10} {'-':<10} {char:<10}")
            continue
        
        # Get the shift value from the keyword
        key_char = keyword[i % key_length]
        shift = ord(key_char) - ord('A')
        
        # Apply the reverse shift
        if char.isalpha():
            # Convert to 0-25 range, apply reverse shift, and convert back
            char_code = (ord(char) - ord('A') - shift) % 26
            decrypted_char = chr(char_code + ord('A'))
            plaintext += decrypted_char
            
            print(f"{char:<10} {key_char:<10} {shift:<10} {decrypted_char:<10}")
    
    return plaintext

def main():
    """
    Main function to handle user input and display results
    """
    print("=" * 50)
    print("Vigenère Cipher - Encryption and Decryption")
    print("Laboratory Exercise 10 - Coding Vegenère")
    print("Desiree Esguerra - BSIT 4A")
    print("=" * 50)
    
    # Get plaintext and keyword from user
    plaintext = input("\nEnter the plaintext message: ")
    keyword = input("Enter the keyword: ")
    
    # Validate the keyword (must be alphabetic)
    if not keyword.isalpha():
        print("Error: Keyword must contain only alphabetic characters.")
        return
    
    # Encrypt the plaintext
    ciphertext = vigenere_encrypt(plaintext, keyword)
    print("\nEncrypted Message (Ciphertext):", ciphertext)
    
    # Decrypt the ciphertext
    decrypted_text = vigenere_decrypt(ciphertext, keyword)
    print("\nDecrypted Message:", decrypted_text)
    
    # Verify the decryption by comparing with original plaintext
    if decrypted_text.upper() == plaintext.upper():
        print("\nVerification: Successful! The decrypted text matches the original plaintext.")
    else:
        print("\nVerification: Failed! The decrypted text does not match the original plaintext.")

if __name__ == "__main__":
    main()
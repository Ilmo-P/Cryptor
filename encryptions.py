from argon2.low_level import hash_secret_raw, Type
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def KDF_16(password:str, salt:bytes = None) -> tuple[bytes,bytes]:
    """Generates a 16 byte long hash and a similar length salt from a given password.

    Args:
        ``password``: A string of characters that will be used to generate the hash and salt.
        ``salt``: A 16 byte long bytes that can optionally be used to generate the hash.
    
    Returns:
        ``[hash_result, salt]``: A tuple where both hash_result and salt are 16 long bytes. 
    """

    if salt is None:
        salt = get_random_bytes(16)
    encoded_password = password.encode("utf-8")

    hash_result = hash_secret_raw(
        secret=encoded_password,
        salt=salt,
        time_cost=2,
        memory_cost=65536,
        parallelism=1,
        hash_len=16,
        type=Type.ID
    )
    return hash_result, salt

def AES_GCM_encrypt(password:str, data:bytes):
    """Takes data and encrypts it using AES GCM with a KDF. Returns the salt, nonce, tag and ciphertext.

    Args:
        ``password``: A string that the KDF will use.
        ``data``: The data in bytes that needs to be encrypted.
    
    Returns:
        ``[salt, nonce, tag, ciphertext]``: A tuple containing everything necessary for decryption. Lengths are [16,12,16,...]
    """
    key, salt = KDF_16(password)

    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return (salt, nonce, tag, ciphertext)

def AES_GCM_decrypt(password:str, salt:bytes, nonce:bytes, tag:bytes, data:bytes):
    """Takes data and decrypts it using AES GCM with a KDF. Returns the plaintext.

    Args:
        ``password``: A string that the KDF will use.
        ``salt``: The salt as bytes used in the original encryption.
        ``nonce``: The nonce as bytes used in the original encryption.
        ``tag``: The MAC tag as bytes returned by the original encryption.
        ``data``: The data as bytes that is going to be decrypted.
    
    Returns:
        ``plaintext``: The original text or string as bytes.
    """
    key, _ = KDF_16(password,salt)
    cipher = AES.new(key,AES.MODE_GCM,nonce)
    cipher.update(salt)
    plaintext = cipher.decrypt_and_verify(data, tag)
    return plaintext

def AES_GCM_encrypt_file(file_path:str, password:str):
    """Encrypts a file at file_path using a KDF and AES GCM. The function does not rename or change the file extension.
    Returns the path of the encrypted file.

    Args:
        ``file_path``: The path pointing to the target file.
        ``password``: A string that the KDF will use.
    
    Returns:
        ``encrypted_path``: The path to the file that has been encrypted. Note that this is the same as file_path if the encryption has been succesful.
    """
    with open(file_path, "rb") as open_file:
        file_data = open_file.read()
    header, nonce, tag, ciphertext = AES_GCM_encrypt(password,file_data)
    encrypted_data = header + nonce + tag + ciphertext
    with open(file_path, 'wb') as open_file:
        open_file.write(encrypted_data)
    return file_path

def AES_GCM_decrypt_file(file_path:str, password:str):
    """Decrypts a file at file_path using a KDF and AES GCM. The function does not rename or change the file extension.
    Returns the path of the decrypted file.

    Args:
        ``file_path``: The path pointing to the encrypted file.
        ``password``: A string that the KDF will use.
    
    Returns:
        ``decrypted_path``: The path to the file that has been decrypted. Note that this is the same as file_path if the decryption is succesful.
    """
    with open(file_path, "rb") as open_file:
        encrypted_data = open_file.read()
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]
    plaindata = AES_GCM_decrypt(password,salt,nonce,tag,ciphertext)
    with open(file_path, 'wb') as open_file:
        open_file.write(plaindata)
    return file_path

def AES_GCM_encrypt_name(file_path:str, password:str):
    """Takes a path to a file or directory that will have its name encrypted.

    Args:
        ``file_path``: A path to the file or directory that will have its name encrypted.
        ``password``: The password that the KDF will be used along with the encryption.
    
    Returns:
        ``encrypted_path``: Contains the path to the file or directory which has had its name encrypted.
    """
    
    def AES_GCM_encrypt_filename(file_path:str, password:str):
        """Encrypts the name of a file and changes its extension to .enc.

        Args:
            ``file_path``: A path containing the location of the file.
            ``password``: A string that the KDF will use to encrypt the file name.
            
        Returns:
            ``new_path``: The path to the file that has had its name encrypted.
        """
        file_dir, file_name = os.path.split(file_path)
        bytes_name = file_name.encode()
        salt, nonce, tag, ciphertext = AES_GCM_encrypt(password,bytes_name)
        new_name = (salt + nonce + tag + ciphertext).hex() + '.enc'
        if len(new_name) >= 256:
            raise ValueError("New name is too long!")
        new_path = os.path.join(file_dir, new_name)
        os.rename(file_path,new_path)
        return new_path

    def AES_GCM_encrypt_dirname(directory_path:str, password:str):
        """Encrypts the name of a directory.

        Args:
            ``directory_path``: The path to the directory that needs to have its name encrypted.
            ``password``: A string that the KDF will use to encrypt the directory name.
            
        Returns:
            ``new_path``: The new path to the directory that has had its name encrypted.
        """
        dir_root_path, directory_name = os.path.split(directory_path)
        encoded_name = directory_name.encode()
        salt, nonce, tag, ciphertext = AES_GCM_encrypt(password, encoded_name)
        new_name = (salt + nonce + tag  + ciphertext).hex()
        if len(new_name) >= 256:
            raise ValueError("New name is too long!")
        new_path = os.path.join(dir_root_path, new_name)
        os.rename(directory_path, new_path)
        return new_path

    if os.path.isfile(file_path):
        encrypted_path = AES_GCM_encrypt_filename(file_path,password)
    elif os.path.isdir(file_path):
        encrypted_path = AES_GCM_encrypt_dirname(file_path,password)
    return encrypted_path

def AES_GCM_decrypt_name(file_path:str, password:str):
    """Takes a path to a file or directory that has had its name encrypted and tries to decrypt it.

    Args:
        ``file_path``: A path to the file or directory which should have its name decrypted.
        ``password``: The password that the KDF will be used along with the decryption.
    
    Returns:
        ``decrypted_path``: Contains the path to the file or folder that has had its name decrypted.
    """

    def AES_GCM_decrypt_filename(file_path:str, password:str):
        """Decrypts the name of the file.

        Args:
            ``file_path``: The path to the file that needs its name changed.
            ``password``: A string that the KDF will use to decrypt the file name.
        
        Returns:
            ``original_path``: If the decryption is succesful the original path will be returned, otherwise the file_path will be returned.
        """
        file_dir, file_name = os.path.split(file_path)
        plain_name = os.path.splitext(file_name)[0]
        bytes_name = bytes.fromhex(plain_name)
        salt = bytes_name[:16]
        nonce = bytes_name[16:28]
        tag = bytes_name[28:44]
        ciphertext = bytes_name[44:]
        plaintext = AES_GCM_decrypt(password,salt,nonce,tag,ciphertext)
        original_name = plaintext.decode()
        original_path = os.path.join(file_dir,original_name)
        os.rename(file_path,original_path)
        return original_path

    def AES_GCM_decrypt_dirname(directory_path:str, password:str):
        """Decrypts the name of the directory.

        Args:
            ``directory_path``: The path to the directory that needs its name changed.
            ``password``: A string that the KDF will use to decrypt the directory name.
        
        Returns:
            ``original_path``: If the decryption is succesful the original path will be returned, otherwise the directory_path will be returned.
        """
        dir_root_path, directory_name = os.path.split(directory_path)
        bytes_name = bytes.fromhex(directory_name)
        salt = bytes_name[:16]
        nonce = bytes_name[16:28]
        tag = bytes_name[28:44]
        ciphertext = bytes_name[44:]
        plaintext = AES_GCM_decrypt(password, salt, nonce, tag, ciphertext)
        original_name = plaintext.decode()
        original_path = os.path.join(dir_root_path,original_name)
        os.rename(directory_path, original_path)
        return original_path

    if os.path.isfile(file_path):
        decrypted_path = AES_GCM_decrypt_filename(file_path,password)
    elif os.path.isdir(file_path):
        decrypted_path = AES_GCM_decrypt_dirname(file_path,password)
    return decrypted_path
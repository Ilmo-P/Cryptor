import os
import file_handling as fh
import encryptions as enc

class EncryptionForm:
    def __init__(self, file_path:str, password:str, filter_extension:str = '', encryption:str = 'AES', encrypt_names:bool = False, compress_files:bool = False ):
        self.file_path = file_path
        self.password = password
        self.filter_extension = filter_extension
        self.encryption = encryption
        self.encrypt_names = encrypt_names
        self.compress_files = compress_files
        self.enc_dirs, self.enc_files = fh.find_targets(file_path,filter_extension)
        self.combined_list = self.enc_files + self.enc_dirs

    def validate(self):
        if not os.path.exists(self.file_path):
            raise ValueError(f"Invalid file path!")

    def compress(self):
        self.enc_files = fh.zip_files(self.enc_files)
    
    def encrypt(self):
        if self.encryption == 'AES':
            for self.i, self.path_file in enumerate(self.enc_files):
                try:
                    print(f"encrypting: {self.path_file}")
                    self.enc_files[self.i] = enc.AES_GCM_encrypt_file(self.path_file, self.password)
                except Exception as e:
                    print(f"Encryption error. {e}")
            self.combined_list = self.enc_files + self.enc_dirs

    def rename(self):
        if self.encryption == 'AES':
            for self.i, self.path_file in enumerate(self.combined_list):
                try:
                    self.combined_list[self.i] = enc.AES_GCM_encrypt_name(self.path_file, self.password)
                except Exception as e:
                    print(f"Renaming error. {e}")

    def run(self):
        self.validate()
        if self.compress_files:
            self.compress()
        self.encrypt()
        if self.encrypt_names:
            self.rename()

class DecryptionForm:
    def __init__(self, file_path:str, password:str, encryption:str = 'AES'):
        self.file_path = file_path
        self.password = password
        self.encryption = encryption
        self.dec_dirs, self.dec_files = fh.find_targets(self.file_path)
        self.combined_list = self.dec_files + self.dec_dirs
        
    def validate(self):
        if len(self.combined_list) == 0:
            print("No paths for decryption were found!")
            pass
    
    def decrypt(self):
        if self.encryption == 'AES':
            for self.i, self.path_file in enumerate(self.dec_files):
                try:
                    self.dec_files[self.i] = enc.AES_GCM_decrypt_file(self.path_file,self.password)
                except Exception as e:
                    print(f"Decryption error. {e}")
            self.combined_list = self.dec_files + self.dec_dirs

    def rename(self):
        if self.encryption == 'AES':
            for self.i, self.path_file in enumerate(self.combined_list):
                try:
                    self.combined_list[self.i] = enc.AES_GCM_decrypt_name(self.path_file,self.password)
                except Exception as e:
                    print(f"Renaming error. {e}")
  
    def decompress(self):
        self.zip_files = fh.find_targets(self.file_path,'.zip')[1]
        fh.unzip_files(self.zip_files)

    def run(self):
        self.validate()
        self.decrypt()
        self.rename()
        self.decompress()

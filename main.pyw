import forms
import customtkinter as CTK
import os

CTK.set_appearance_mode("dark")
CTK.set_default_color_theme("green")

class TabsFrame(CTK.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.encryption_tab = CTK.CTkButton(self, text="Encryption", command=self.select_encryption, corner_radius=0)
        self.encryption_tab.grid(row=0, column=0, sticky="ew")
        self.decryption_tab = CTK.CTkButton(self, text="Decryption", command=self.select_decryption, corner_radius=0)
        self.decryption_tab.grid(row=0, column=1, sticky="ew")

    def select_encryption(self):
        root.remove_frame()
        root.render_encryption_frame()

    def select_decryption(self):
        root.remove_frame()
        root.render_decryption_frame()

class EncryptionFrame(CTK.CTkFrame):
    def __init__(self,master):
        super().__init__(master)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=3)

        self.file_path_label = CTK.CTkLabel(self, text="File path:")
        self.file_path_label.grid(row=0, column=0, padx=10, sticky="w")
        self.file_path_entry = CTK.CTkEntry(self)
        self.file_path_entry.grid(row=0, column=1, pady=(10,5), padx=(0,10))

        self.file_type_label = CTK.CTkLabel(self, text="File extension:")
        self.file_type_label.grid(row=1, column=0, padx=10, sticky="w")
        self.file_type_entry = CTK.CTkEntry(self)
        self.file_type_entry.grid(row=1, column=1, pady=5, padx=(0,10))

        self.password_label = CTK.CTkLabel(self, text="Password:")
        self.password_label.grid(row=2, column=0, padx=10, sticky="w")
        self.password_entry = CTK.CTkEntry(self, show="*")
        self.password_entry.grid(row=2, column=1, pady=5, padx=(0,10))

        self.password_again_label = CTK.CTkLabel(self, text="Password again:")
        self.password_again_label.grid(row=3, column=0, padx=10, sticky="w")
        self.password_again_entry = CTK.CTkEntry(self, show="*")
        self.password_again_entry.grid(row=3, column=1, pady=5, padx=(0,10))

        self.encrypt_names_checkbox = CTK.CTkCheckBox(self, text="Encrypt names")
        self.encrypt_names_checkbox.grid(row=4,column=0, padx=(10,0), pady=(10,5), sticky="w")

        self.compress_checkbox = CTK.CTkCheckBox(self, text="Compress files")
        self.compress_checkbox.grid(row=5,column=0, padx=(10,0), pady=(10,5), sticky="w")

        self.encrypt_button = CTK.CTkButton(self, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=6, column=0, pady=(10,5), columnspan=2)

    def get_values(self):
        self.file_path = self.file_path_entry.get()
        self.extension = self.file_type_entry.get()
        self.password = self.password_entry.get()
        self.password_again = self.password_again_entry.get()
        self.encrypt_names = self.encrypt_names_checkbox.get()
        self.compress = self.compress_checkbox.get()
    
    def render_error(self, error:str):
        if hasattr(self, "warning_label"):
            self.warning_label.destroy()
        self.warning_label = CTK.CTkLabel(self, text=error, text_color="red")
        self.warning_label.grid(row=7, column=0, pady=(0,5), columnspan=2)
    
    def check_input(self):
        if not os.path.exists(self.file_path):
            self.render_error("Invalid file path!")
            raise Exception("Invalid file path!")
        if self.password != self.password_again:
            self.render_error("Passwords do not match!")
            raise Exception("Passwords do not match!")
        if len(self.password) < 6:
            self.render_error("Password is too short!")
            raise Exception("Password is too short!")
        return True

    def encrypt(self):
        self.get_values()
        self.check_input()
        enc_form = forms.EncryptionForm(self.file_path,self.password,self.extension,'AES',self.encrypt_names,self.compress)
        enc_form.run()
        if hasattr(self, "warning_label"):
            self.warning_label.destroy()

class DecryptionFrame(CTK.CTkFrame):
    def __init__(self, master):
        super().__init__(master)

        self.file_path_label = CTK.CTkLabel(self, text="File path:")
        self.file_path_label.grid(row=0, column=0, padx=10, sticky="w")
        self.file_path_entry = CTK.CTkEntry(self)
        self.file_path_entry.grid(row=0, column=1, pady=(10,5), padx=(0,10))

        self.password_label = CTK.CTkLabel(self, text="Password:")
        self.password_label.grid(row=2, column=0, padx=10, sticky="w")
        self.password_entry = CTK.CTkEntry(self, show="*")
        self.password_entry.grid(row=2, column=1, pady=5, padx=(0,10))
        
        self.encrypt_button = CTK.CTkButton(self, text="Decrypt", command=self.decrypt)
        self.encrypt_button.grid(row=5, column=0, pady=10, columnspan=2)

    def get_values(self):
        self.file_path = self.file_path_entry.get()
        self.password = self.password_entry.get()
    
    def decrypt(self):
        self.get_values()
        dec_form = forms.DecryptionForm(self.file_path,self.password)
        dec_form.run()

class Root(CTK.CTk):
    def __init__(self):
        super().__init__()
        self.grid_columnconfigure(0,weight=1)
    
        self.title("Cryptor")
        self.geometry("600x400")

        self.tabs_frame = TabsFrame(self)
        self.tabs_frame.grid(row=0, column=0, pady=(0,10), sticky="ew")

        self.render_encryption_frame()
    
    def render_encryption_frame(self):
        self.current_frame = EncryptionFrame(self)
        self.current_frame.grid(row=1, column=0)

    def render_decryption_frame(self):
        self.current_frame = DecryptionFrame(self)
        self.current_frame.grid(row=1, column=0)

    def remove_frame(self):
        self.current_frame.destroy()

root = Root()

def main():
    root.mainloop()

if __name__ == "__main__":
    main()
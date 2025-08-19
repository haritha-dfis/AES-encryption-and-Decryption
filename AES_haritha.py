import base64
import tkinter as tk
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def update_fields(*args):
    """Show/Hide Key & IV fields depending on action"""
    if action_var.get() == "Decrypt":
        key_label.pack(pady=2)
        key_entry.pack()
        iv_label.pack(pady=2)
        iv_entry.pack()
    else:
        key_label.pack_forget()
        key_entry.pack_forget()
        iv_label.pack_forget()
        iv_entry.pack_forget()


def process_action():
    action = action_var.get()
    
    if action == "Encrypt":
        plaintext_message = main_input.get("1.0", tk.END).strip()
        if not plaintext_message:
            messagebox.showerror("Error", "Please enter plaintext to encrypt.")
            return
        
        try:
            key = get_random_bytes(32)  # AES-256 key
            iv = get_random_bytes(16)   # IV

            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = pad(plaintext_message.encode('utf-8'), AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)

            # Encode in Base64
            key_b64 = base64.b64encode(key).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

            output_box.delete("1.0", tk.END)
            output_box.insert(tk.END,
                f"Secret Key (Base64): {key_b64}\n"
                f"IV (Base64): {iv_b64}\n"
                f"Ciphertext (Base64): {ciphertext_b64}\n"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))

    elif action == "Decrypt":
        ciphertext_b64 = main_input.get("1.0", tk.END).strip()
        key_b64 = key_entry.get("1.0", tk.END).strip()
        iv_b64 = iv_entry.get("1.0", tk.END).strip()

        if not ciphertext_b64 or not key_b64 or not iv_b64:
            messagebox.showerror("Error", "Please enter ciphertext, key, and IV.")
            return

        try:
            key = base64.b64decode(key_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)

            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_message = unpad(decrypted_padded, AES.block_size).decode('utf-8')

            output_box.delete("1.0", tk.END)
            output_box.insert(tk.END, f"Decrypted Plaintext: {decrypted_message}\n")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


# --- GUI Setup ---
root = tk.Tk()
root.title("AES model")
root.geometry("750x600")

# Mode Selector
tk.Label(root, text="Choose Action:", font=("Arial", 13)).pack()
action_var = tk.StringVar(value="Encrypt")
action_menu = tk.OptionMenu(root, action_var, "Encrypt", "Decrypt")
action_menu.pack(pady=5)
action_var.trace("w", update_fields)  # Call update_fields when selection changes

# Main Input
tk.Label(root, text="Input (Plaintext /Ciphertext):", font=("Arial", 13)).pack()
main_input = scrolledtext.ScrolledText(root, height=4, width=80)
main_input.pack()

# Key and IV (hidden initially, only shown for decrypt)
key_label = tk.Label(root, text="Secret Key (Base64):", font=("Times New Roman", 13))
key_entry = scrolledtext.ScrolledText(root, height=2, width=80)

iv_label = tk.Label(root, text="IV (Base64):", font=("Times New Roman", 13))
iv_entry = scrolledtext.ScrolledText(root, height=2, width=80)

# Run Button
tk.Button(root, text="Encrypt/Decrypt", command=process_action, bg="Green").pack(pady=10)

# Output
tk.Label(root, text="Output:", font=("Arial", 14)).pack()
output_box = scrolledtext.ScrolledText(root, height=8, width=80)
output_box.pack()

root.mainloop()

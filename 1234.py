import tkinter as tk
from tkinter import messagebox
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad


def decrypt_message():
    key = decryption_key_entry.get()[:8].encode()

    # Debug message
    print("Waiting for connection from sender...")

    # Receive the encrypted message from the sender
    sender_ip = '127.0.0.1'  # Change this to the IP address of the sender
    sender_port = 5578  # Change this to the port number used by the sender
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((sender_ip, sender_port))
        s.listen()
        conn, addr = s.accept()

        # Debug message
        print("Connection established with sender.")

        encrypted_message = conn.recv(1024).decode()

        # Debug message
        print("Received encrypted message from sender.")

    try:
        encrypted_message_bytes = bytes.fromhex(encrypted_message)
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message_bytes)
        unpadded_message = unpad(decrypted_message, DES.block_size)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Decrypted Message:\n" + unpadded_message.decode())
        result_text.config(state=tk.DISABLED)
    except ValueError:
        messagebox.showerror("Error", "Invalid hexadecimal input.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# GUI setup
root = tk.Tk()
root.title("Message Decryption")

label_key = tk.Label(root, text="Decryption Key (8 characters):")
label_key.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

decryption_key_entry = tk.Entry(root, width=40)
decryption_key_entry.grid(row=0, column=1, padx=10, pady=5)

decrypt_button = tk.Button(root, text="Decrypt Message", command=decrypt_message)
decrypt_button.grid(row=1, column=0, columnspan=2, pady=10)

result_text = tk.Text(root, width=50, height=7)
result_text.grid(row=2, column=0, columnspan=2, padx=10, pady=5)
result_text.config(state=tk.DISABLED)

root.mainloop()

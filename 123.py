import tkinter as tk
from tkinter import messagebox
import socket
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad


def encrypt_email(email, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_email = pad(email.encode(), DES.block_size)
    encrypted_email = cipher.encrypt(padded_email)
    return encrypted_email.hex()


def encrypt_and_send_email():
    encryption_key = encryption_key_entry.get()[:8].encode()
    sender_email = sender_entry.get()
    recipient_email = recipient_entry.get()
    email_to_encrypt = email_entry.get("1.0", tk.END).strip()  # Get text from the Text widget

    if not encryption_key or not sender_email or not recipient_email or not email_to_encrypt:
        messagebox.showerror("Error", "Please fill in all fields.")
        return

    message = f"From: {sender_email}\nTo: {recipient_email}\n\n{email_to_encrypt}"
    encrypted_message = encrypt_email(message, encryption_key)

    # Debug messages
    print("Connecting to receiver...")

    # Send the encrypted message to the receiver
    receiver_ip = '127.0.0.1'  # Change this to the IP address of the receiver
    receiver_port = 5578  # Change this to the port number used by the receiver
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((receiver_ip, receiver_port))

        # Debug message
        print("Connected to receiver.")

        s.sendall(encrypted_message.encode())

        # Debug message
        print("Encrypted message sent to receiver.")

    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Encrypted Email Sent")
    result_text.config(state=tk.DISABLED)


# GUI setup
root = tk.Tk()
root.title("Email Encryption")
root.geometry("400x400")

label_sender = tk.Label(root, text="Sender's Email:")
label_sender.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

sender_entry = tk.Entry(root, width=40)
sender_entry.grid(row=0, column=1, padx=10, pady=5)

label_recipient = tk.Label(root, text="Recipient's Email:")
label_recipient.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

recipient_entry = tk.Entry(root, width=40)
recipient_entry.grid(row=1, column=1, padx=10, pady=5)

label_email = tk.Label(root, text="Email to Encrypt:")
label_email.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

email_entry = tk.Text(root, width=40, height=7)
email_entry.grid(row=2, column=1, padx=10, pady=5)

label_encryption_key = tk.Label(root, text="Encryption Key (8 characters):")
label_encryption_key.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

encryption_key_entry = tk.Entry(root, width=40)
encryption_key_entry.grid(row=3, column=1, padx=10, pady=5)

encrypt_button = tk.Button(root, text="Encrypt and Send Email", command=encrypt_and_send_email)
encrypt_button.grid(row=4, column=0, columnspan=2, pady=10)

result_text = tk.Text(root, width=60, height=7)
result_text.grid(row=5, column=0, columnspan=2, padx=10, pady=5)
result_text.config(state=tk.DISABLED)

root.mainloop()

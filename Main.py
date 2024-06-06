import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap, wrpcap

def compare_pcap(file1, file2, output_file):
    packets1 = rdpcap(file1)
    packets2 = rdpcap(file2)
    
    packets1_set = set(p.summary() for p in packets1)
    unique_packets = [p for p in packets2 if p.summary() not in packets1_set]
    
    wrpcap(output_file, unique_packets)
    messagebox.showinfo("Success", f"Unique packets written to {output_file}")

def select_file1():
    file1_path.set(filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")]))
    
def select_file2():
    file2_path.set(filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")]))
    
def compare_files():
    file1 = file1_path.get()
    file2 = file2_path.get()
    if not file1 or not file2:
        messagebox.showwarning("Input Error", "Please select both PCAP files.")
        return
    output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if output_file:
        compare_pcap(file1, file2, output_file)

# Set up the Tkinter window
root = tk.Tk()
root.title("PCAP File Comparator")

file1_path = tk.StringVar()
file2_path = tk.StringVar()

tk.Label(root, text="Select first PCAP file:").grid(row=0, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=file1_path, width=50).grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=select_file1).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Select second PCAP file:").grid(row=1, column=0, padx=10, pady=10)
tk.Entry(root, textvariable=file2_path, width=50).grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=select_file2).grid(row=1, column=2, padx=10, pady=10)

tk.Button(root, text="Compare", command=compare_files).grid(row=2, column=0, columnspan=3, pady=20)

root.mainloop()

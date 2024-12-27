from tkinter import ttk

import tkinter as tk
import socket
import threading

def scan_port(ip, port, results):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Устанавливаем таймаут 1 секунда
            if s.connect_ex((ip, port)) == 0:
                results[port] = "Открыт"
            else:
                results[port] = "Закрыт"
    except Exception as e:
        results[port] = f"Ошибка: {e}"


def scan_ports():
    ip = ip_entry.get()
    start_port = int(start_port_entry.get())
    end_port = int(end_port_entry.get())

    results = {}
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(ip, port, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    output_text.delete("1.0", tk.END)
    for port, status in results.items():
        output_text.insert(tk.END, f"Порт {port}: {status}\n")


root = tk.Tk()
root.title("Port scanner")
root.geometry('403x403+0+0')
root.resizable(False, False)
ttk.Style().theme_use('xpnative')

ip_label = ttk.Label(root, text="IP-адрес:")
ip_label.place(x=10, y=10)
ip_entry = ttk.Entry(root, width=33)
ip_entry.place(x=150, y = 10)

start_port_label = ttk.Label(root, text="Начальный порт:")
start_port_label.place(x=10, y =40)
start_port_entry = ttk.Entry(root, width=33)
start_port_entry.place(x=150, y=40)

end_port_label = ttk.Label(root, text="Конечный порт:")
end_port_label.place(x=10, y=70)
end_port_entry = ttk.Entry(root, width=33)
end_port_entry.place(x=150, y=70)

scan_button = ttk.Button(root, text="Сканировать", command=scan_ports, width=53, cursor='hand2')
scan_button.place(x=10, y=100)

output_text = tk.Text(root, wrap=tk.WORD, width=42, height=15, borderwidth=1, relief='solid')
output_text.place(x=10, y=135)

root.mainloop()

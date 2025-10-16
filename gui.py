import re
import tkinter as tk
from pathlib import Path
from tkinter import Canvas, Entry, Button, PhotoImage, messagebox


def is_valid_ip(ip):
    """Validate the IP address format."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if re.match(pattern, ip):
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False


def on_button_click():
    """Validate IP and display message."""
    ip_address = entry_1.get()
    if is_valid_ip(ip_address):
        messagebox.showinfo("Success", f"Valid IP: {ip_address}")
        # Here, you can call a function to perform a network scan
    else:
        messagebox.showerror("Error", "Invalid IP Address! Please enter a correct one.")


OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"D:\python\build\assets\frame0")


def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


window = tk.Tk()
window.geometry("600x400")
window.configure(bg="#FFFFFF")

canvas = Canvas(
    window,
    bg="#FFFFFF",
    height=400,
    width=600,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)
canvas.place(x=0, y=0)

canvas.create_rectangle(313.0, 0.0, 600.0, 406.0, fill="#0A1332", outline="")

canvas.create_text(
    394.0, 45.0,
    anchor="nw",
    text="SAFEHAVEN",
    fill="#FFFFFF",
    font=("GajrajOne Regular", 20 * -1)
)

canvas.create_text(
    326.0, 151.0,
    anchor="nw",
    text="ENTER THE IP ADDRESS:",
    fill="#FFFFFF",
    font=("GajrajOne Regular", 20 * -1)
)

entry_image_1 = PhotoImage(file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(453.5, 209.5, image=entry_image_1)

entry_1 = Entry(
    bd=0,
    bg="#D9D9D9",
    fg="#000716",
    highlightthickness=0
)
entry_1.place(x=332.0, y=192.0, width=243.0, height=33.0)

canvas.create_text(
    325.0, 87.0,
    anchor="nw",
    text="To use our website, you will need to enter\nthe IP address of the network that you \nwant to scan and make sure it is secure.",
    fill="#FFFFFF",
    font=("Galindo Regular", 12 * -1)
)

button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(
    image=button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=on_button_click,
    relief="flat"
)
button_1.place(x=372.0, y=250.0, width=140.0, height=55.0)

button_image_hover_1 = PhotoImage(file=relative_to_assets("button_hover_1.png"))


def button_1_hover(e):
    button_1.config(image=button_image_hover_1)


def button_1_leave(e):
    button_1.config(image=button_image_1)


button_1.bind('<Enter>', button_1_hover)
button_1.bind('<Leave>', button_1_leave)

image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(156.0, 200.0, image=image_image_1)

window.resizable(False, False)
window.mainloop()

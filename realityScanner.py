import os
import re
import sys
import webbrowser
import requests
import urllib.request
import socket
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
import tldextract
from tkinter import ttk
from tkinter import messagebox
from threading import Thread
import customtkinter


class ScannerApp:
    URL_MAIN = "https://bgp.tools"
    URL_ROUTE = "/prefix"
    URL = URL_MAIN + URL_ROUTE

    TIMEOUT = 3

    def __init__(self):
        customtkinter.set_appearance_mode("system")
        customtkinter.set_default_color_theme("blue")

        self.root = customtkinter.CTk()
        self.root.title("Reality Friendly Scanner | Coded by: @B3H1")
        self.root.minsize(500, 500)

        self.icon_path = self.resource_path("assets/icon.ico")
        self.root.iconbitmap(self.icon_path)

        self.create_table()
        self.create_input_fields()
        self.create_progress_bar()

    def resource_path(self, relative_path):
        base_path = getattr(
            sys,
            '_MEIPASS',
            os.path.dirname(os.path.abspath(__file__))
        )
        return os.path.join(base_path, relative_path)

    def create_table(self):
        self.table = ttk.Treeview(
            self.root, columns=('URL', 'IP', 'Info'), show='headings', height=15
        )

        self.table.bind('<Double-1>', self.copy_cell_content)

        self.table.heading('URL', text='URL')
        self.table.heading('IP', text='IP')
        self.table.heading('Info', text='Info')

        self.table.column('URL', width=200)
        self.table.column('IP', width=200)
        self.table.column('Info', width=300)

        self.table.pack(pady=10)

    def create_input_fields(self):
        self.ip_label = customtkinter.CTkLabel(
            self.root, text="Your server IP address", fg_color="transparent"
        )
        self.ip_label.pack(pady=5)

        self.ip_entry = customtkinter.CTkEntry(self.root, placeholder_text="IP:")
        self.ip_entry.pack(pady=5)

        self.search_button = customtkinter.CTkButton(
            master=self.root, text="Search", command=self.search_input
        )
        self.search_button.pack(pady=10)

    def create_progress_bar(self):
        self.percentage_label = customtkinter.CTkLabel(
            self.root, text="0%", fg_color="transparent"
        )
        self.percentage_label.pack(side='right', anchor='w', padx="10")

        self.progress_bar = customtkinter.CTkProgressBar(
            self.root, orientation="horizontal", width=100
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(side='right', anchor='w', pady="10")

        self.link = customtkinter.CTkLabel(
            self.root, text="About", font=('Helvetica', 15), cursor="hand2",
            padx="10"
        )
        self.link.pack(side='left')
        self.link.bind("<Button-1>", lambda e: self.callback("https://behnam.cloud"))

    def copy_cell_content(self, event):
        item = self.table.selection()[0]
        column_id = self.table.identify_column(event.x)
        cell_content = self.table.item(item)['values'][0]

        self.root.clipboard_clear()
        self.root.clipboard_append(cell_content)

        messagebox.showinfo("Domain Copied", f"{cell_content} copied to clipboard.")

    def add_row(self, url, ip, info):
        self.table.insert('', 'end', values=(url, ip, info))

    def log_label_set(self, text):
        self.ip_label.configure(text=f"{text}")

    def callback(self, url):
        webbrowser.open_new_tab(url)

    def search_input(self):
        ip_search = self.ip_entry.get()
        thread = Thread(target=self.run, args=(ip_search,))
        thread.start()

    def send_request(self, ip):
        ua = UserAgent()
        header = {'User-Agent': ua.random}

        try:
            res = requests.get(
                f"{self.URL}/{ip}", headers=header, timeout=self.TIMEOUT
            )
            if res.status_code == 403:
                self.log_label_set("Your IP BLOCKED by bgp.tools")
        except requests.exceptions.RequestException as e:
            try:
                res_try = requests.get(self.URL_MAIN, headers=header, timeout=5)
                if res_try.status_code == 403:
                    self.log_label_set("Your IP BLOCKED by bgp.tools")
                    return False
            except requests.exceptions.RequestException as e:
                self.log_label_set("Cannot connect to bgp.tools \n Check your internet connection")
                return False
            self.log_label_set("Cannot connect to bgp.tools \n Please try again")

            return False
        return res

    def cipher_checker(self, domain):
        context = socket.create_default_context()
        try:
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock_version = ssock.version()
                    ssock_cipher = ssock.cipher()
            return ssock_cipher
        except socket.error:
            pass

    def domain_ip_range_checker(self, domain):
        ip = socket.gethostbyname(domain)
        if ip:
            return ip

    def domain_checker(self, domain):
        domain = domain.replace(" ", "")
        domain_s = f"https://{domain}"
        try:
            status = urllib.request.urlopen(domain_s, timeout=self.TIMEOUT).getcode()
            if status == 200:
                ssock_cipher = self.cipher_checker(domain)
                ssock_version = ssock_cipher[1]
                if ssock_version == "TLSv1.3":
                    dns = self.domain_ip_range_checker(domain)
                    return domain, ssock_cipher, dns
                else:
                    return False
        except urllib.error.URLError:
            return False

    def check_useless_domain(self, url):
        regex_ip_in_domain = r'(?:[0-9]{1,3}\-){2}[0-9]{1,3}|(?:[0-9]{1,3}\.){2}[0-9]{1,3}'
        regex_subdomain = r'[.-]'
        if not re.findall(regex_ip_in_domain, url):
            ext = tldextract.extract(url)
            if not re.search(regex_subdomain, ext[0]):
                if not ext[0] == 'mail':
                    return True
        return False

    def fdns_html_parser(self, html):
        domains = []
        if not html:
            return False
        soup = BeautifulSoup(html.text, 'html.parser')
        table = soup.find('table', id='fdnstable')
        if table:
            all_tr = table.findAll('tr')
            all_tr.pop(0)
            for tr in all_tr:
                _domain = tr.find('td', {'class': 'smallonmobile nowrap'})
                if _domain.text:
                    _domain = _domain.text
                    if _domain.find(",") != -1:
                        _domain = _domain.split(",")
                        for domain in _domain:
                            domain = domain.replace(" ", "")
                            if domain.find('(') != -1:
                                domain = domain.split("(")[0]
                            domain = domain.replace(" ", "").strip()
                            domains.append(domain)
                    else:
                        domains.append(_domain)
        return domains

    def rdns_html_parser(self, html):
        domains = []
        if not html:
            return False
        soup = BeautifulSoup(html.text, 'html.parser')
        table = soup.find('table', id='rdnstable')
        if table:
            all_tr = table.findAll('tr')
            all_tr.pop(0)
            for tr in all_tr:
                _domain = tr.find('td', {'class': 'smallonmobile nowrap'})
                if _domain.text[-1] == ".":
                    _domain = _domain.text[:-1]
                else:
                    _domain = _domain.text
                domains.append(_domain)
        return domains

    def run_dns(self, domains):
        if domains:
            all_count = len(domains)
            count = 0
            for domain in domains:
                self.log_label_set(domain)
                if self.check_useless_domain(domain):
                    st = self.domain_checker(domain)
                    if st:
                        domain, ssock_cipher, dns = st
                        self.add_row(domain, dns, ssock_cipher)
                count += 1
                prog = round((count / all_count) * 100)
                self.percentage_label.configure(text=f"{prog}%")
                self.progress_bar.set(prog / 100)
                self.root.update()
        else:
            self.log_label_set("There is no domain")
        self.progress_bar.stop()

    def validate_ipv4_address(self, address):
        ipv4_pattern = (
            r"^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        return re.match(ipv4_pattern, address)

    def run(self, input_ip):
        if self.validate_ipv4_address(input_ip):
            self.log_label_set("Waiting for getting data from bgp.tools ...")
            html_response = self.send_request(input_ip)
            if html_response:
                rdns = self.rdns_html_parser(html_response)
                fdns = self.fdns_html_parser(html_response)
                self.log_label_set("Checking Reversed Dns Domains ...")
                self.run_dns(rdns)
                self.log_label_set("Checking Forward Dns Domains ...")
                self.run_dns(fdns)
                self.log_label_set("Done!")
        else:
            self.log_label_set("Please Enter a Valid IPv4 address")
            self.progress_bar.stop()


if __name__ == "__main__":
    app = ScannerApp()
    app.root.mainloop()

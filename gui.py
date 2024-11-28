# gui.py

import os
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, END
import threading
from antivirus import Antivirus
import shutil
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import logging
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

try:
    from plyer import notification
except ImportError:
    notification = None
    print("Warning: 'plyer' module not found. Notifications will be disabled.")

try:
    import pystray
    from PIL import Image, ImageDraw
except ImportError:
    pystray = None
    print("Warning: 'pystray' module not found. System tray icon will be disabled.")

class AntivirusGUI:
    def __init__(self, master):
        self.master = master
        master.title('Neural Network Antivirus')
        master.geometry('900x700')
        master.resizable(True, True)

        # Apply a theme
        self.style = ttk.Style('flatly')  # Use a modern theme

        self.antivirus = Antivirus()
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.notifications = []
        self.threat_history = []

        # Configure logging
        logging.basicConfig(
            filename='antivirus.log',
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s:%(message)s',
            encoding='utf-8'
        )

        # Create GUI components
        self.create_menu()
        self.create_widgets()

        # System tray icon
        if pystray:
            self.create_system_tray_icon()

        # Handle window closing
        self.master.protocol('WM_DELETE_WINDOW', self.on_closing)

    def create_menu(self):
        menu_bar = ttk.Menu(self.master)

        # File Menu
        file_menu = ttk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label='Scan File', command=self.scan_file)
        file_menu.add_command(label='Scan Directory', command=self.scan_directory)
        file_menu.add_separator()
        file_menu.add_command(label='Exit', command=self.exit_application)
        menu_bar.add_cascade(label='File', menu=file_menu)

        # Settings Menu
        settings_menu = ttk.Menu(menu_bar, tearoff=0)
        # Theme Submenu
        theme_menu = ttk.Menu(settings_menu, tearoff=0)
        themes = self.style.theme_names()
        for theme in themes:
            theme_menu.add_command(label=theme.capitalize(), command=lambda t=theme: self.change_theme(t))
        settings_menu.add_cascade(label='Change Theme', menu=theme_menu)
        settings_menu.add_command(label='Preferences', command=self.open_settings)
        menu_bar.add_cascade(label='Settings', menu=settings_menu)

        # Help Menu
        help_menu = ttk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label='About', command=self.show_about)
        menu_bar.add_cascade(label='Help', menu=help_menu)

        self.master.config(menu=menu_bar)

    def change_theme(self, theme_name):
        self.style.theme_use(theme_name)

    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.master)
        main_frame.pack(fill=BOTH, expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=BOTH, expand=True)

        # Dashboard Tab
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text='Dashboard')
        self.create_dashboard(self.dashboard_tab)

        # Scan Tab
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text='Scan')
        self.create_scan_tab(self.scan_tab)

        # Quarantine Manager Tab
        self.quarantine_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_tab, text='Quarantine')
        self.create_quarantine_tab(self.quarantine_tab)

        # Threat History Tab
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text='Threat History')
        self.create_history_tab(self.history_tab)

    def create_dashboard(self, parent):
        status_label = ttk.Label(parent, text='System Status:', font=('Helvetica', 16, 'bold'))
        status_label.pack(pady=10)

        # Protection Status
        self.protection_status = ttk.Label(parent, text='Protected', font=('Helvetica', 14), foreground='green')
        self.protection_status.pack(pady=5)

        # Last Scan Time
        last_scan_label = ttk.Label(parent, text='Last Scan:', font=('Helvetica', 12))
        last_scan_label.pack(pady=5)

        self.last_scan_time = ttk.Label(parent, text='Never', font=('Helvetica', 12))
        self.last_scan_time.pack(pady=5)

        # Real-Time Protection Toggle
        self.real_time_var = ttk.BooleanVar(value=True)
        real_time_toggle = ttk.Checkbutton(
            parent, text='Enable Real-Time Protection', variable=self.real_time_var,
            bootstyle='success-round-toggle', command=self.toggle_real_time_protection)
        real_time_toggle.pack(pady=10)

        # Quick Actions
        quick_actions_label = ttk.Label(parent, text='Quick Actions:', font=('Helvetica', 14, 'bold'))
        quick_actions_label.pack(pady=10)

        actions_frame = ttk.Frame(parent)
        actions_frame.pack(pady=5)

        scan_now_btn = ttk.Button(actions_frame, text='Scan Now', command=self.scan_directory, bootstyle='primary')
        scan_now_btn.pack(side=LEFT, padx=5)

        update_btn = ttk.Button(actions_frame, text='Update', command=self.update_definitions, bootstyle='secondary')
        update_btn.pack(side=LEFT, padx=5)

    def create_scan_tab(self, parent):
        # Scan Controls
        scan_frame = ttk.Frame(parent)
        scan_frame.pack(pady=10)

        scan_file_btn = ttk.Button(scan_frame, text='Scan File', command=self.scan_file)
        scan_file_btn.pack(side=LEFT, padx=10)

        scan_dir_btn = ttk.Button(scan_frame, text='Scan Directory', command=self.scan_directory)
        scan_dir_btn.pack(side=LEFT, padx=10)

        # Output Text Area
        self.output_text = ttk.Text(parent, wrap='word', height=20)
        self.output_text.pack(fill=BOTH, expand=True, padx=10, pady=5)

        # Clear Output Button
        self.clear_output_btn = ttk.Button(parent, text='Clear Output', command=self.clear_output)
        self.clear_output_btn.pack(pady=10)

    def create_quarantine_tab(self, parent):
        # Quarantine Manager
        columns = ('#1', '#2')
        self.quarantine_tree = ttk.Treeview(parent, columns=columns, show='headings')
        self.quarantine_tree.heading('#1', text='File Name')
        self.quarantine_tree.heading('#2', text='Date Quarantined')
        self.quarantine_tree.pack(fill=BOTH, expand=True)

        # Buttons to restore or delete files
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text='Restore File', command=self.restore_file).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text='Delete File', command=self.delete_file).pack(side=LEFT, padx=5)

        self.load_quarantine()

    def create_history_tab(self, parent):
        # Threat History
        columns = ('#1', '#2', '#3')
        self.history_tree = ttk.Treeview(parent, columns=columns, show='headings')
        self.history_tree.heading('#1', text='Date')
        self.history_tree.heading('#2', text='File')
        self.history_tree.heading('#3', text='Action')
        self.history_tree.pack(fill=BOTH, expand=True)

        # Add buttons for deleting and saving history
        button_frame = ttk.Frame(parent)
        button_frame.pack(pady=10)

        delete_history_btn = ttk.Button(button_frame, text='Delete History', command=self.delete_history)
        delete_history_btn.pack(side=LEFT, padx=5)

        save_history_btn = ttk.Button(button_frame, text='Save History as PDF', command=self.save_history_as_pdf)
        save_history_btn.pack(side=LEFT, padx=5)

    def delete_history(self):
        confirm = messagebox.askyesno('Delete History', 'Are you sure you want to delete the scan history?')
        if confirm:
            # Clear the threat history list and treeview
            self.threat_history.clear()
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            messagebox.showinfo('Delete History', 'Scan history has been deleted.')

    def save_history_as_pdf(self):
        file_path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF files', '*.pdf')])
        if file_path:
            try:
                c = canvas.Canvas(file_path, pagesize=letter)
                width, height = letter

                c.setFont('Helvetica-Bold', 16)
                c.drawString(50, height - 50, 'Threat History Report')

                c.setFont('Helvetica', 12)
                y_position = height - 80

                for entry in self.threat_history:
                    date_str, file_name, action = entry
                    line = f'Date: {date_str} | File: {file_name} | Action: {action}'
                    c.drawString(50, y_position, line)
                    y_position -= 20
                    if y_position < 50:
                        c.showPage()
                        y_position = height - 50

                c.save()
                messagebox.showinfo('Save History', f'Scan history has been saved as {file_path}.')
            except Exception as e:
                messagebox.showerror('Error', f'Failed to save history as PDF: {e}')

    def load_quarantine(self):
        # Clear existing items
        for item in self.quarantine_tree.get_children():
            self.quarantine_tree.delete(item)

        quarantine_dir = self.antivirus.quarantine_dir
        for file_name in os.listdir(quarantine_dir):
            file_path = os.path.join(quarantine_dir, file_name)
            date_quarantined = time.ctime(os.path.getctime(file_path))
            self.quarantine_tree.insert('', END, values=(file_name, date_quarantined))

    def toggle_real_time_protection(self):
        if self.real_time_var.get():
            self.protection_status.config(text='Protected', foreground='green')
            # Start real-time protection
        else:
            self.protection_status.config(text='Not Protected', foreground='red')
            # Stop real-time protection

    def update_definitions(self):
        # Simulate checking for updates
        messagebox.showinfo('Update', 'Virus definitions are up to date.')
        # In a real application, implement actual update logic

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.executor.submit(self.scan_file_thread, file_path)

    def scan_file_thread(self, file_path):
        try:
            message, status = self.antivirus.scan_file(file_path)
            self.output_text.insert(END, message + '\n')
            # Update last scan time
            self.last_scan_time.config(text=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            # Add to threat history if malware detected or unknown
            if status in ['Quarantined', 'Unknown']:
                self.threat_history.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), os.path.basename(file_path), status))
                self.history_tree.insert('', END, values=self.threat_history[-1])
                if status == 'Quarantined':
                    self.load_quarantine()
            if notification:
                self.master.after(0, self.notify_user, 'Scan Complete', f'Scan of {file_path} completed.')
        except Exception as e:
            error_message = f'Error scanning {file_path}: {str(e)}'
            self.output_text.insert(END, error_message + '\n')
            logging.error(error_message, exc_info=True)

    def scan_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.executor.submit(self.scan_directory_thread, directory)

    def scan_directory_thread(self, directory):
        try:
            total_files = sum(len(files) for _, _, files in os.walk(directory))
            scanned_files = 0

            progress = ttk.Progressbar(self.scan_tab, maximum=total_files)
            progress.pack(fill=X, padx=10, pady=5)

            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    message, status = self.antivirus.scan_file(file_path)
                    self.output_text.insert(END, message + '\n')
                    scanned_files += 1
                    progress['value'] = scanned_files
                    # Update last scan time
                    self.last_scan_time.config(text=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                    # Add to threat history if malware detected or unknown
                    if status in ['Quarantined', 'Unknown']:
                        self.threat_history.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), os.path.basename(file_path), status))
                        self.history_tree.insert('', END, values=self.threat_history[-1])
                        if status == 'Quarantined':
                            self.load_quarantine()

            progress.destroy()
            if notification:
                self.master.after(0, self.notify_user, 'Scan Complete', f'Scan of {directory} completed.')
        except Exception as e:
            error_message = f'Error scanning directory {directory}: {str(e)}'
            self.output_text.insert(END, error_message + '\n')
            logging.error(error_message, exc_info=True)

    def clear_output(self):
        self.output_text.delete('1.0', END)

    def restore_file(self):
        selected_item = self.quarantine_tree.selection()
        if selected_item:
            file_name = self.quarantine_tree.item(selected_item)['values'][0]
            quarantine_path = os.path.join(self.antivirus.quarantine_dir, file_name)
            original_path = filedialog.askdirectory(title='Select Restore Location')
            if original_path:
                try:
                    shutil.move(quarantine_path, os.path.join(original_path, file_name))
                    self.quarantine_tree.delete(selected_item)
                    messagebox.showinfo('Restore File', f'File {file_name} has been restored.')
                except Exception as e:
                    messagebox.showerror('Error', f'Failed to restore file: {e}')
        else:
            messagebox.showwarning('Restore File', 'No file selected.')

    def delete_file(self):
        selected_item = self.quarantine_tree.selection()
        if selected_item:
            file_name = self.quarantine_tree.item(selected_item)['values'][0]
            quarantine_path = os.path.join(self.antivirus.quarantine_dir, file_name)
            confirm = messagebox.askyesno('Delete File', f'Are you sure you want to delete {file_name}?')
            if confirm:
                try:
                    os.remove(quarantine_path)
                    self.quarantine_tree.delete(selected_item)
                    messagebox.showinfo('Delete File', f'File {file_name} has been deleted.')
                except Exception as e:
                    messagebox.showerror('Error', f'Failed to delete file: {e}')
        else:
            messagebox.showwarning('Delete File', 'No file selected.')

    def open_settings(self):
        settings_window = ttk.Toplevel(self.master)
        settings_window.title('Settings')
        settings_window.geometry('400x300')
        settings_window.resizable(False, False)

        # Example settings
        ttk.Label(settings_window, text='Update Interval (minutes):').pack(pady=10)
        update_interval_var = ttk.IntVar(value=60)
        ttk.Entry(settings_window, textvariable=update_interval_var).pack()

        ttk.Label(settings_window, text='Enable Real-Time Protection:').pack(pady=10)
        real_time_var = ttk.BooleanVar(value=True)
        ttk.Checkbutton(settings_window, variable=real_time_var).pack()

        ttk.Button(settings_window, text='Save', command=settings_window.destroy).pack(pady=20)

    def show_about(self):
        messagebox.showinfo('About', 'Neural Network Antivirus\nVersion 1.0\nDeveloped by Your Name')

    def notify_user(self, title, message):
        if notification:
            notification.notify(
                title=title,
                message=message,
                app_name='Neural Network Antivirus',
                timeout=5
            )

    def create_system_tray_icon(self):
        if not pystray:
            return
        # Create an icon image
        image = Image.new('RGB', (64, 64), color='blue')
        draw = ImageDraw.Draw(image)
        draw.rectangle((0, 0, 64, 64), fill='blue')

        # Define menu items
        menu = (
            pystray.MenuItem('Show', self.show_window),
            pystray.MenuItem('Exit', self.exit_application)
        )

        self.icon = pystray.Icon('antivirus', image, 'Neural Network Antivirus', menu)
        threading.Thread(target=self.icon.run, daemon=True).start()

    def show_window(self, icon, item):
        self.master.after(0, self.master.deiconify)

    def exit_application(self, icon=None, item=None):
        if icon:
            icon.stop()
        self.master.quit()

    def on_closing(self):
        self.master.withdraw()
        # If needed, show a balloon message or notification
        # self.notify_user('Antivirus', 'Application minimized to tray.')

# Run the GUI
if __name__ == '__main__':
    root = ttk.Window(themename='flatly')
    gui = AntivirusGUI(root)
    root.mainloop()

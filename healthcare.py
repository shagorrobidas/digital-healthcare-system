import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
from datetime import datetime, timedelta
import re
import bcrypt
import time
import random
import string
import smtplib
from email.mime.text import MIMEText


class HealthcareSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Healthcare System")
        self.root.geometry("1000x800")

        # Database initialization
        self.conn = sqlite3.connect('healthcaredamo.db')
        self.create_tables()

        # Login state
        self.current_user = None
        self.current_role = None
        self.current_user_id = None
        self.login_time = None

        # Styling
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#4CAF50") # noqa
        self.style.configure("TLabel", font=("Arial", 10))

        # Create login screen
        self.create_login_screen()

    def create_tables(self):
        cursor = self.conn.cursor()
        # Patients table with additional fields
        cursor.execute('''CREATE TABLE IF NOT EXISTS patients
                        (id INTEGER PRIMARY KEY, name TEXT, dob TEXT, contact TEXT, email TEXT,
                            address TEXT, gender TEXT, blood_group TEXT, emergency_contact TEXT,
                            medical_history TEXT)''')   # noqa
        # Appointments table
        cursor.execute('''CREATE TABLE IF NOT EXISTS appointments
                        (id INTEGER PRIMARY KEY, patient_id INTEGER, doctor_id INTEGER, 
                            date TEXT, time TEXT, status TEXT)''') # noqa

        # Prescriptions table
        cursor.execute('''CREATE TABLE IF NOT EXISTS prescriptions
                (id INTEGER PRIMARY KEY, patient_id INTEGER,
                        doctor_id INTEGER, 
                        appointment_id INTEGER, symptoms TEXT, diagnosis TEXT, medication TEXT, 
                        dosage TEXT, frequency TEXT, duration TEXT, instructions TEXT, 
                        tests TEXT, followup_date TEXT, lifestyle TEXT, warnings TEXT, 
                        date TEXT)''') # noqa

        # Employees table (includes doctors)
        cursor.execute('''CREATE TABLE IF NOT EXISTS employees
                        (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, 
                            role TEXT, status TEXT, full_name TEXT, specialty TEXT, phone TEXT)''') # noqa
        # Pharmacy table (fixed typo)
        cursor.execute('''CREATE TABLE IF NOT EXISTS pharmacy   
                        (id INTEGER PRIMARY KEY, medication TEXT, quantity INTEGER, threshold INTEGER,
                        expiry_date TEXT, status TEXT)''')  # noqa
        # Activity log table
        cursor.execute('''CREATE TABLE IF NOT EXISTS activity_log
                        (id INTEGER PRIMARY KEY, username TEXT, action TEXT, timestamp TEXT)''')    # noqa
        # Doctor schedules table
        cursor.execute('''CREATE TABLE IF NOT EXISTS doctor_schedules
                        (id INTEGER PRIMARY KEY, doctor_id INTEGER, date TEXT, start_time TEXT, 
                            end_time TEXT, status TEXT)''') # noqa
        self.conn.commit()

        # Create default admin user if not exists
        cursor.execute("SELECT * FROM employees WHERE username = 'admin'")
        if not cursor.fetchone():
            hashed = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()) # noqa
            cursor.execute("INSERT INTO employees (username, password, email, role, status, full_name) VALUES (?, ?, ?, ?, ?, ?)", # noqa
                            ('admin', hashed, 'admin@healthcare.com', 'admin', 'approved', 'Admin User')) # noqa
            self.conn.commit()

    def log_activity(self, action):
        if self.current_user:
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO activity_log (username, action, timestamp) VALUES (?, ?, ?)",   # noqa
                            (self.current_user, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))  # noqa
            self.conn.commit()

    def check_session_timeout(self):
        """Check if session has timed out and return False if expired"""
        if self.login_time and (time.time() - self.login_time) > 1200:
            messagebox.showwarning(
                "Session Timeout", "Session has expired. Please login again."
            )
            self.logout()
            return False
        return True

    def create_login_screen(self):
        self.clear_window()
        tk.Label(
            self.root,
            text="Digital Healthcare System",
            font=("Arial", 25, "bold")
        ).pack(pady=20)
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Username:", font=("Arial", 10)).grid(
            row=0, column=0, padx=5, pady=5
        )
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:", font=("Arial", 10)).grid(
            row=1, column=0, padx=5, pady=5
        )
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Login", command=self.login).grid(
            row=2, column=0, pady=10
        )
        ttk.Button(
            frame, text="Register", command=self.create_registration_screen
        ).grid(row=2, column=1, pady=10)

    def create_registration_screen(self):
        self.clear_window()
        tk.Label(self.root, text="Employee Registration", font=(
            "Arial", 16, "bold"
        )).pack(pady=20)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Username:", font=("Arial", 10)).grid(
            row=0, column=0, padx=5, pady=5
        )
        username_entry = tk.Entry(frame)
        username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Full Name:", font=("Arial", 10)).grid(
            row=1, column=0, padx=5, pady=5
        )
        full_name_entry = tk.Entry(frame)
        full_name_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Email:", font=("Arial", 10)).grid(
            row=2, column=0, padx=5, pady=5
        )
        email_entry = tk.Entry(frame)
        email_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(frame, text="Phone:", font=("Arial", 10)).grid(
            row=3, column=0, padx=5, pady=5
        )
        phone_entry = tk.Entry(frame)
        phone_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:", font=("Arial", 10)).grid(
            row=4, column=0, padx=5, pady=5
        )
        password_entry = tk.Entry(frame, show="*")
        password_entry.grid(row=4, column=1, padx=5, pady=5)

        tk.Label(frame, text="Confirm Password:", font=("Arial", 10)).grid(
            row=5, column=0, padx=5, pady=5
        )
        confirm_password_entry = tk.Entry(frame, show="*")
        confirm_password_entry.grid(row=5, column=1, padx=5, pady=5)

        tk.Label(frame, text="Role:", font=("Arial", 10)).grid(
            row=6, column=0, padx=5, pady=5
        )
        role_var = tk.StringVar(value="staff")
        tk.Radiobutton(
            frame, text="Admin", variable=role_var, value="admin"
        ).grid(row=6, column=1, sticky="w")

        tk.Radiobutton(
            frame, text="Staff", variable=role_var, value="staff"
        ).grid(row=6, column=1)
        tk.Radiobutton(
            frame, text="Doctor", variable=role_var, value="doctor"
        ).grid(row=6, column=1, sticky="e")

        tk.Label(
            frame, text="Specialty (if Doctor):", font=("Arial", 10)
        ).grid(row=7, column=0, padx=5, pady=5)
        specialty_entry = tk.Entry(frame)
        specialty_entry.grid(row=7, column=1, padx=5, pady=5)

        # CAPTCHA
        self.captcha_text = ''.join(
            random.choices(string.ascii_uppercase + string.digits, k=6)
        )

        tk.Label(
            frame,
            text=f"CAPTCHA: {self.captcha_text}", font=("Arial", 10, "bold")
        ).grid(row=8, column=0, padx=5, pady=5)
        captcha_entry = tk.Entry(frame)
        captcha_entry.grid(row=8, column=1, padx=5, pady=5)

        ttk.Button(
            frame, text="Register", command=lambda: self.register_employee(
                username_entry.get(),
                full_name_entry.get(),
                email_entry.get(),
                phone_entry.get(),
                password_entry.get(),
                confirm_password_entry.get(),
                role_var.get(),
                specialty_entry.get(),
                captcha_entry.get())
        ).grid(row=9, column=0, columnspan=2, pady=10)

        ttk.Button(
            self.root, text="Back to Login", command=self.create_login_screen
        ).pack(pady=10)

    def register_employee(
            self,
            username, full_name, email, phone,
            password, confirm_password, role, specialty, captcha
            ):
        if not all([username, full_name, email, phone, password, confirm_password, captcha]): # noqa
            messagebox.showerror("Error", "Please fill all fields")
            return

        if captcha != self.captcha_text:
            messagebox.showerror("Error", "Invalid CAPTCHA")
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format")
            return

        if not re.match(r"^\+?\d{10,15}$", phone):
            messagebox.showerror("Error", "Invalid phone number format")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password):   # noqa
        #     messagebox.showerror("Error", "Password must be 8+ characters with uppercase, lowercase, number, and special character") # noqa
        #     return

        if role == "doctor" and not specialty:
            messagebox.showerror("Error", "Specialty is required for doctors")
            return

        cursor = self.conn.cursor()
        try:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("INSERT INTO employees (username, password, email, role, status, full_name, specialty, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",   # noqa 
                            (username, hashed, email, role, "pending", full_name, specialty, phone)) # noqa
            self.conn.commit()
            self.log_activity(f"New registration request: {username} ({role})")
            messagebox.showinfo(
                "Success", "Registration submitted. Wait admin approval."
            )
            self.create_login_screen()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE username = ? AND status = 'approved'", (username,)) # noqa
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            self.current_user = username
            self.current_role = user[4]
            self.current_user_id = user[0]
            self.login_time = time.time()
            self.log_activity(f"Login: {username}")
            self.create_main_menu()
        else:
            messagebox.showerror(
                "Error", "Invalid credentials or account not approved"
            )

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def create_main_menu(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(
            self.root,
            text=f"Welcome, {self.current_user} ({self.current_role})",
            font=("Arial", 14, "bold")
        ).pack(pady=10)

        # Check for pending registrations (admin only)
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM employees WHERE status = 'pending'"
        )
        pending_count = cursor.fetchone()[0]
        if pending_count > 0 and self.current_role == "admin":
            messagebox.showinfo(
                "Pending Registrations",
                f"There are {pending_count} pending employee registrations"
            )

        # Check for upcoming appointments
        self.check_appointment_reminders()

        frame = tk.Frame(self.root)
        frame.pack(pady=20)

        buttons = [
            # ("Change Password", self.change_password)
            
        ]

        if self.current_role == "admin":
            buttons.extend([
                ("Patient Management", self.patient_management),
                ("Employee Management", self.employee_management),
                ("Appointment Scheduling", self.appointment_scheduling),
                ("Pharmacy Management", self.pharmacy_management),
                ("View Doctor Info", self.view_doctor_info),
                # ("View Patient Info", self.view_patient_info),
                ("Activity Log", self.view_activity_log),
                ("Doctor Schedules", self.doctor_schedule_management),
                ("Change Password", self.change_password),
            ])
        elif self.current_role == "doctor":
            buttons.extend([
                ("Patient details and add", self.patient_management),
                ("Prescription Management", self.prescription_management),
                ("View Doctor Info", self.view_doctor_info),
                ("My Schedule", self.view_doctor_schedule),
                ("Prescription Analytics", self.prescription_analytics),
                ("Change Password", self.change_password),
            ])
        elif self.current_role == "staff":
            buttons.extend([
                ("Patient Management", self.patient_management),
                ("Appointment Scheduling", self.appointment_scheduling),
                ("Pharmacy Management", self.pharmacy_management),
                ("Change Password", self.change_password),
            ])

        for text, command in buttons:
            ttk.Button(
                frame, text=text, command=command, width=25
            ).pack(pady=5)

        ttk.Button(
            frame, text="Logout", command=self.create_login_screen, width=25
        ).pack(pady=20)

    def change_password(self):
        """Allow the current user to change their password"""
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Change Password", font=("Arial", 14, "bold")).pack(pady=10)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Current Password:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        current_password_entry = tk.Entry(frame, show="*")
        current_password_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="New Password:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        new_password_entry = tk.Entry(frame, show="*")
        new_password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Confirm New Password:", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        confirm_password_entry = tk.Entry(frame, show="*")
        confirm_password_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Change Password", command=lambda: self.process_change_password(
            current_password_entry.get(), new_password_entry.get(), confirm_password_entry.get())).grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=10)

    def process_change_password(self, current_password, new_password, confirm_password):
        """Process the password change request"""
        if not all([current_password, new_password, confirm_password]):
            messagebox.showerror("Error", "Please fill all fields")
            return

        if new_password != confirm_password:
            messagebox.showerror("Error", "New passwords do not match")
            return

        # Validate new password strength (optional)
        # if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", new_password):
        #     messagebox.showerror("Error", "New password must be at least 8 characters with uppercase, lowercase, number, and special character")
            # return

        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM employees WHERE id = ? AND status = 'approved'", (self.current_user_id,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(current_password.encode('utf-8'), user[0]):
            hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE employees SET password = ? WHERE id = ?", (hashed_new_password, self.current_user_id))
            self.conn.commit()
            self.log_activity(f"Password changed for user: {self.current_user}")
            messagebox.showinfo("Success", "Password changed successfully")
            self.create_main_menu()
        else:
            messagebox.showerror("Error", "Current password is incorrect")

    # def check_appointment_reminders(self):
    #     cursor = self.conn.cursor()
    #     tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
    #     if self.current_role == "doctor":
    #         cursor.execute("SELECT patient_id, date, time FROM appointments WHERE date = ? AND status = 'Scheduled' AND doctor_id = ?",      # noqa
    #                         (tomorrow, self.current_user_id)) # noqa
    #     else:
    #         cursor.execute("SELECT patient_id, date, time, doctor_id FROM appointments WHERE date = ? AND status = 'Scheduled'", # noqa
    #                         (tomorrow,)) # noqa
    #     appointments = cursor.fetchall()
    #     if appointments:
    #         reminder = "\n".join([f"Reminder: Patient ID {row[0]} at {row[2]} on {row[1]}"  # noqa
    #                             for row in appointments]) # noqa
    #         messagebox.showinfo("Appointment Reminders", reminder)
    
    def check_appointment_reminders(self):
        cursor = self.conn.cursor()
        tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        if self.current_role == "doctor":
            cursor.execute("SELECT patient_id, date, time FROM appointments WHERE date = ? AND status = 'Scheduled' AND doctor_id = ?",      # noqa
                            (tomorrow, self.current_user_id)) # noqa
        else:
            cursor.execute("SELECT patient_id, date, time, doctor_id FROM appointments WHERE date = ? AND status = 'Scheduled'", # noqa
                            (tomorrow,)) # noqa
        appointments = cursor.fetchall()
        if appointments:
            reminder = "\n".join([f"Reminder: Patient ID {row[0]} at {row[2]} on {row[1]}"  # noqa
                                for row in appointments]) # noqa
            messagebox.showinfo("Appointment Reminders", reminder)

    def patient_management(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(
            self.root, text="Patient Management", font=("Arial", 14, "bold")
        ).pack(pady=10)

        # Search bar
        search_frame = tk.Frame(self.root)
        search_frame.pack(pady=5)
        tk.Label(search_frame, text="Search by Name:").pack(side=tk.LEFT)
        search_entry = tk.Entry(search_frame)
        search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(
            search_frame, text="Search", command=lambda: self.search_patients(
                search_entry.get()
            )
        ).pack(side=tk.LEFT)

        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(
            frame, text="Name:", font=("Arial", 10)
        ).grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(frame)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="DOB (YYYY-MM-DD):", font=("Arial", 10)
        ).grid(row=1, column=0, padx=5, pady=5)
        dob_entry = tk.Entry(frame)
        dob_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Contact:", font=("Arial", 10)
        ).grid(row=2, column=0, padx=5, pady=5)
        contact_entry = tk.Entry(frame)
        contact_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Email:", font=("Arial", 10)
        ).grid(row=3, column=0, padx=5, pady=5)
        email_entry = tk.Entry(frame)
        email_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Address:", font=("Arial", 10)
        ).grid(row=4, column=0, padx=5, pady=5)
        address_entry = tk.Entry(frame)
        address_entry.grid(row=4, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Gender:", font=("Arial", 10)
        ).grid(row=5, column=0, padx=5, pady=5)
        gender_var = tk.StringVar(value="Male")
        tk.Radiobutton(
            frame, text="Male", variable=gender_var, value="Male"
        ).grid(row=5, column=1, sticky="w")
        tk.Radiobutton(
            frame, text="Female", variable=gender_var, value="Female"
        ).grid(row=5, column=1, sticky="e")

        tk.Label(
            frame, text="Blood Group:", font=("Arial", 10)
        ).grid(row=6, column=0, padx=5, pady=5)
        blood_group_var = tk.StringVar()
        blood_groups = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
        ttk.Combobox(
            frame, textvariable=blood_group_var, values=blood_groups
        ).grid(row=6, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Emergency Contact:", font=("Arial", 10)
        ).grid(row=7, column=0, padx=5, pady=5)
        emergency_contact_entry = tk.Entry(frame)
        emergency_contact_entry.grid(row=7, column=1, padx=5, pady=5)

        tk.Label(
            frame, text="Medical History:", font=("Arial", 10)
        ).grid(row=8, column=0, padx=5, pady=5)
        history_entry = tk.Text(frame, height=5, width=50)
        history_entry.grid(row=8, column=1, padx=5, pady=5)

        ttk.Button(frame, text="Add Patient", command=lambda: self.add_patient(
            name_entry.get(), dob_entry.get(), contact_entry.get(),
            email_entry.get(),
            address_entry.get(), gender_var.get(), blood_group_var.get(),
            emergency_contact_entry.get(), history_entry.get("1.0", tk.END)
        )).grid(row=9, column=0, columnspan=2, pady=10)

        # Patient list
        self.patient_tree_frame = tk.Frame(self.root)
        self.patient_tree_frame.pack(pady=10)
        self.patient_tree = ttk.Treeview(
            self.patient_tree_frame,
            columns=("ID", "Name", "DOB", "Contact", "Email", "Gender", "Blood Group"), # noqa
            show="headings"
        )
        self.patient_tree.heading("ID", text="ID")
        self.patient_tree.heading("Name", text="Name")
        self.patient_tree.heading("DOB", text="DOB")
        self.patient_tree.heading("Contact", text="Contact")
        self.patient_tree.heading("Email", text="Email")
        self.patient_tree.heading("Gender", text="Gender")
        self.patient_tree.heading("Blood Group", text="Blood Group")
        self.patient_tree.pack()

        # Double-click to view patient details
        self.patient_tree.bind("<Double-1>", self.show_patient_details)

        self.search_patients("")

        ttk.Button(
            self.root, text="Back", command=self.create_main_menu
        ).pack(pady=5)

    def show_patient_details(self, event):
        selected = self.patient_tree.selection()
        if not selected:
            return

        patient_id = self.patient_tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
        patient = cursor.fetchone()

        details_window = tk.Toplevel(self.root)
        details_window.title("Patient Details")
        details_window.geometry("400x500")

        tk.Label(
            details_window, text="Patient Details", font=("Arial", 12, "bold")
        ).pack(pady=10)

        fields = ["ID", "Name", "DOB", "Contact", "Email", "Address", "Gender", "Blood Group", "Emergency Contact", "Medical History"]   # noqa
        for i, (field, value) in enumerate(zip(fields, patient)):
            tk.Label(details_window, text=f"{field}: {value}").pack(pady=5)

        if self.current_role == "doctor":
            ttk.Button(
                details_window, text="View Appointment History",
                command=lambda: self.view_patient_appointment_history(
                    patient_id
                )
            ).pack(pady=5)
            ttk.Button(
                details_window, text="View Prescription History",
                command=lambda: self.view_patient_prescription_history(
                    patient_id
                )
            ).pack(pady=5)

        ttk.Button(
            details_window, text="Close", command=details_window.destroy
        ).pack(pady=10)

    def view_patient_appointment_history(self, patient_id):
        history_window = tk.Toplevel(self.root)
        history_window.title("Patient Appointment History")
        history_window.geometry("600x400")

        tk.Label(
            history_window,
            text="Appointment History", font=("Arial", 12, "bold")
        ).pack(pady=10)

        tree = ttk.Treeview(
            history_window,
            columns=("ID", "Doctor", "Date", "Time", "Status"),
            show="headings"
        )
        tree.heading("ID", text="ID")
        tree.heading("Doctor", text="Doctor")
        tree.heading("Date", text="Date")
        tree.heading("Time", text="Time")
        tree.heading("Status", text="Status")
        tree.pack(pady=10)

        cursor = self.conn.cursor()
        cursor.execute("SELECT a.id, e.full_name, a.date, a.time, a.status FROM appointments a JOIN employees e ON a.doctor_id = e.id WHERE a.patient_id = ?",(patient_id,)) # noqa
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)

        ttk.Button(
            history_window, text="Close", command=history_window.destroy
        ).pack(pady=5)

    def view_patient_prescription_history(self, patient_id):
        history_window = tk.Toplevel(self.root)
        history_window.title("Patient Prescription History")
        history_window.geometry("600x400")

        tk.Label(
            history_window,
            text="Prescription History", font=("Arial", 12, "bold")
        ).pack(pady=10)

        tree = ttk.Treeview(
            history_window,
            columns=("ID", "Medication", "Dosage", "Instructions", "Date"),
            show="headings"
        )
        tree.heading("ID", text="ID")
        tree.heading("Medication", text="Medication")
        tree.heading("Dosage", text="Dosage")
        tree.heading("Instructions", text="Instructions")
        tree.heading("Date", text="Date")
        tree.pack(pady=10)

        cursor = self.conn.cursor()
        cursor.execute("SELECT id, medication, dosage, instructions, date FROM prescriptions WHERE patient_id = ?",(patient_id,)) # noqa
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)

        # Download prescription option
        tree.bind("<Double-1>", lambda e: self.download_prescription(tree, patient_id)) # noqa
        
        ttk.Button(
            history_window, text="Close", command=history_window.destroy
        ).pack(pady=5)

    def download_prescription(self, tree, patient_id):
        selected = tree.selection()
        if not selected:
            return

        prescription_id = tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        cursor.execute("SELECT p.medication, p.dosage, p.instructions, p.date, e.full_name, e.specialty, pat.name "     # noqa
                        "FROM prescriptions p "         # noqa
                        "JOIN employees e ON p.doctor_id = e.id "
                        "JOIN patients pat ON p.patient_id = pat.id "
                        "WHERE p.id = ?", (prescription_id,)
        ) # noqa
        prescription = cursor.fetchone()

        if prescription:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt", filetypes=[("Text files", "*.txt")]
            )
            if filename:
                with open(filename, "w") as f:
                    f.write("Prescription Details\n")
                    f.write(f"Patient: {prescription[6]}\n")
                    f.write(
                        f"Doctor: Dr. {prescription[4]}, {prescription[5]}\n"
                    )
                    f.write(f"Date: {prescription[3]}\n")
                    f.write(f"Medication: {prescription[0]}\n")
                    f.write(f"Dosage: {prescription[1]}\n")
                    f.write(f"Instructions: {prescription[2]}\n")
                messagebox.showinfo(
                    "Success", f"Prescription saved to {filename}"
                )
                self.log_activity(
                    f"Downloaded prescription ID {prescription_id} for patient ID {patient_id}"     # noqa
                )

    def search_patients(self, search_term):
        for item in self.patient_tree.get_children():
            self.patient_tree.delete(item)

        cursor = self.conn.cursor()
        query = "SELECT id, name, dob, contact, email, gender, blood_group FROM patients WHERE name LIKE ?"     # noqa
        cursor.execute(query, (f"%{search_term}%",))
        for row in cursor.fetchall():
            self.patient_tree.insert("", tk.END, values=row)

    def add_patient(self, name, dob, contact, email, address, gender,
                    blood_group, emergency_contact, history):
        if not all([name, dob, contact, email, address,
                    gender, blood_group, emergency_contact]):
            messagebox.showerror("Error", "Please fill all required fields")
            return

        if not re.match(r"\d{4}-\d{2}-\d{2}", dob):
            messagebox.showerror(
                "Error", "Invalid DOB format (use YYYY-MM-DD)"
            )
            return

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format")
            return

        if not re.match(r"^\+?\d{10,15}$", contact):
            messagebox.showerror("Error", "Invalid contact number format")
            return

        if not re.match(r"^\+?\d{10,15}$", emergency_contact):
            messagebox.showerror(
                "Error", "Invalid emergency contact number format"
            )
            return

        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO patients (name, dob, contact, email, address, gender, blood_group, emergency_contact, medical_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", # noqa
                        (name, dob, contact, email, address, gender,
                            blood_group, emergency_contact, history.strip()))
        self.conn.commit()
        self.log_activity(f"Added patient: {name}")
        messagebox.showinfo("Success", "Patient added successfully")
        self.patient_management()
    
    def appointment_scheduling(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Appointment Scheduling", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        # Patient ID and Name
        tk.Label(frame, text="Patient ID:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        patient_id_entry = tk.Entry(frame)
        patient_id_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Label to display patient name
        patient_name_label = tk.Label(frame, text="Patient Name: ", font=("Arial", 10))
        patient_name_label.grid(row=0, column=2, padx=5, pady=5)
        
        # Function to validate patient ID and display name
        def validate_patient_id(*args):
            patient_id = patient_id_entry.get()
            if patient_id:
                try:
                    patient_id = int(patient_id)
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT name FROM patients WHERE id = ?", (patient_id,))
                    patient = cursor.fetchone()
                    if patient:
                        patient_name_label.config(text=f"Patient Name: {patient[0]}")
                    else:
                        patient_name_label.config(text="Patient Name: Invalid ID")
                except ValueError:
                    patient_name_label.config(text="Patient Name: Invalid ID")
            else:
                patient_name_label.config(text="Patient Name: ")

        # Bind validation to patient ID entry
        patient_id_entry.bind("<KeyRelease>", validate_patient_id)
        patient_id_entry.bind("<FocusOut>", validate_patient_id)
        
        tk.Label(frame, text="Doctor:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        doctor_var = tk.StringVar()
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, full_name, specialty FROM employees WHERE role = 'doctor' AND status = 'approved'")
        doctors = [(row[0], f"Dr. {row[1]}, {row[2]}") for row in cursor.fetchall()]
        doctor_dropdown = ttk.Combobox(frame, textvariable=doctor_var, 
                                    values=[d[1] for d in doctors])
        doctor_dropdown.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Date (YYYY-MM-DD):", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        date_entry = tk.Entry(frame)
        date_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Time (HH:MM):", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        time_var = tk.StringVar()
        time_dropdown = ttk.Combobox(frame, textvariable=time_var, state="readonly")
        time_dropdown.grid(row=3, column=1, padx=5, pady=5)
        
        ttk.Button(frame, text="Load Available Times", 
                command=lambda: self.populate_available_times(doctor_var.get(), date_entry.get(), time_dropdown)).grid(row=4, column=0, pady=5)
        
        ttk.Button(frame, text="Check Availability", 
                command=lambda: self.check_doctor_availability(doctor_var.get(), date_entry.get(), time_var.get(), patient_id_entry.get())).grid(row=4, column=1, pady=5)
        
        ttk.Button(frame, text="Book Appointment", 
                command=lambda: self.book_appointment(patient_id_entry.get(), doctor_var.get(), date_entry.get(), time_var.get())).grid(row=5, column=0, columnspan=2, pady=5)
        
        # Doctor's appointments (if doctor)
        if self.current_role == "doctor":
            tk.Label(self.root, text="My Appointments", font=("Arial", 12, "bold")).pack(pady=10)
            
            doctor_appt_frame = tk.Frame(self.root)
            doctor_appt_frame.pack(pady=10)
            
            self.doctor_appt_tree = ttk.Treeview(doctor_appt_frame, 
                                                columns=("ID", "Patient", "Date", "Time", "Status"), 
                                                show="headings")
            self.doctor_appt_tree.heading("ID", text="ID")
            self.doctor_appt_tree.heading("Patient", text="Patient")
            self.doctor_appt_tree.heading("Date", text="Date")
            self.doctor_appt_tree.heading("Time", text="Time")
            self.doctor_appt_tree.heading("Status", text="Status")
            self.doctor_appt_tree.pack()
            
            self.load_doctor_appointments()
            
            btn_frame = tk.Frame(self.root)
            btn_frame.pack(pady=5)
            ttk.Button(btn_frame, text="Complete Appointment", 
                    command=self.complete_appointment).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Cancel Appointment", 
                    command=self.cancel_appointment).pack(side=tk.LEFT, padx=5)
        
        # General appointment list
        tk.Label(self.root, text="All Appointments", font=("Arial", 12, "bold")).pack(pady=10)
        
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, columns=("ID", "Patient ID", "Patient Name", "Doctor", "Date", "Time", "Status"), 
                        show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Patient ID", text="Patient ID")
        tree.heading("Patient Name", text="Patient Name")
        tree.heading("Doctor", text="Doctor")
        tree.heading("Date", text="Date")
        tree.heading("Time", text="Time")
        tree.heading("Status", text="Status")
        tree.pack(pady=5)
        
        cursor.execute(
            """
            SELECT a.id, a.patient_id, p.name, e.full_name, a.date, a.time, a.status 
            FROM appointments a 
            JOIN patients p ON a.patient_id = p.id 
            JOIN employees e ON a.doctor_id = e.id
            """
        )
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)

    def check_doctor_availability(self, doctor_name, date, time, patient_id):
        if not all([doctor_name, date, time, patient_id]):
            messagebox.showerror("Error", "Please fill all fields")
            return

        # Validate patient ID and get name
        try:
            patient_id = int(patient_id)
            cursor = self.conn.cursor()
            cursor.execute("SELECT name FROM patients WHERE id = ?", (patient_id,))
            patient = cursor.fetchone()
            if not patient:
                messagebox.showerror("Error", f"Invalid patient ID: {patient_id}")
                return
            patient_name = patient[0]
        except ValueError:
            messagebox.showerror("Error", "Invalid patient ID format")
            return

        # Validate date and time formats
        try:
            datetime.strptime(date, "%Y-%m-%d")
            if not re.match(r"^\d{2}:\d{2}$", time):
                raise ValueError
            datetime.strptime(time, "%H:%M")
        except ValueError:
            messagebox.showerror("Error", "Invalid date (use YYYY-MM-DD) or time (use HH:MM) format")
            return

        # Extract doctor_id from doctor_name
        cursor.execute(
            "SELECT id FROM employees WHERE full_name LIKE ? AND role = 'doctor' AND status = 'approved'",
            (f"%{doctor_name.split(',')[0].replace('Dr. ', '')}%",)
        )
        doctor = cursor.fetchone()
        if not doctor:
            messagebox.showerror("Error", "Invalid doctor selected")
            return

        doctor_id = doctor[0]

        # Check doctor's schedule
        cursor.execute(
            """
            SELECT id, start_time, end_time FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? 
            AND start_time <= ? AND end_time >= ? 
            AND status = 'Available'
            """,
            (doctor_id, date, time, time)
        )
        schedule = cursor.fetchone()
        if not schedule:
            self.show_available_slots(doctor_id, date, patient_id, patient_name)
            return

        # Check for conflicting appointments
        cursor.execute(
            """
            SELECT id FROM appointments 
            WHERE doctor_id = ? AND date = ? AND time = ? AND status = 'Scheduled'
            """,
            (doctor_id, date, time)
        )
        conflicting_appointment = cursor.fetchone()
        if conflicting_appointment:
            messagebox.showerror(
                "Error", 
                f"Time slot {time} on {date} is already booked for patient ID: {patient_id} ({patient_name})"
            )
            self.show_available_slots(doctor_id, date, patient_id, patient_name)
            return

        messagebox.showinfo(
            "Success", 
            f"Time slot {time} on {date} is available for patient ID: {patient_id} ({patient_name})"
        )

    def show_available_slots(self, doctor_id, date, patient_id, patient_name):
        cursor = self.conn.cursor()
        
        # Fetch doctor's schedule
        cursor.execute(
            """
            SELECT start_time, end_time FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? AND status = 'Available'
            """,
            (doctor_id, date)
        )
        schedules = cursor.fetchall()
        
        if not schedules:
            messagebox.showerror(
                "Error", 
                f"No available schedules for patient ID: {patient_id} ({patient_name}) on {date}"
            )
            return

        # Fetch booked times
        cursor.execute(
            """
            SELECT time FROM appointments 
            WHERE doctor_id = ? AND date = ? AND status = 'Scheduled'
            """,
            (doctor_id, date)
        )
        booked_times = [row[0] for row in cursor.fetchall()]

        # Generate available time slots
        available_slots = []
        for start_time, end_time in schedules:
            start_dt = datetime.strptime(f"{date} {start_time}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date} {end_time}", "%Y-%m-%d %H:%M")
            
            current_dt = start_dt
            while current_dt < end_dt:
                slot_time = current_dt.strftime("%H:%M")
                if slot_time not in booked_times:
                    available_slots.append(slot_time)
                current_dt += timedelta(minutes=30)

        if not available_slots:
            messagebox.showerror(
                "Error", 
                f"No available time slots for patient ID: {patient_id} ({patient_name}) on {date}"
            )
            return

        slots_message = "\n".join(available_slots)
        messagebox.showinfo(
            "Available Time Slots",
            f"No available slot at the selected time for patient ID: {patient_id} ({patient_name}). "
            f"Available time slots on {date}:\n{slots_message}"
        )


    def appointment_scheduling(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Appointment Scheduling", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        tk.Label(frame, text="Patient ID:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        patient_id_entry = tk.Entry(frame)
        patient_id_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Doctor:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        doctor_var = tk.StringVar()
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, full_name, specialty FROM employees WHERE role = 'doctor' AND status = 'approved'")
        doctors = [(row[0], f"Dr. {row[1]}, {row[2]}") for row in cursor.fetchall()]
        doctor_dropdown = ttk.Combobox(frame, textvariable=doctor_var, 
                                    values=[d[1] for d in doctors])
        doctor_dropdown.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Date (YYYY-MM-DD):", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        date_entry = tk.Entry(frame)
        date_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Time (HH:MM):", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        time_var = tk.StringVar()
        time_dropdown = ttk.Combobox(frame, textvariable=time_var, state="readonly")
        time_dropdown.grid(row=3, column=1, padx=5, pady=5)
        
        # Button to populate time slots
        ttk.Button(frame, text="Load Available Times", 
                command=lambda: self.populate_available_times(doctor_var.get(), date_entry.get(), time_dropdown)).grid(row=4, column=0, pady=5)
        
        ttk.Button(frame, text="Check Availability", 
                command=lambda: self.check_doctor_availability(doctor_var.get(), date_entry.get(), time_var.get())).grid(row=4, column=1, pady=5)
        
        ttk.Button(frame, text="Book Appointment", 
                command=lambda: self.book_appointment(patient_id_entry.get(), doctor_var.get(), date_entry.get(), time_var.get())).grid(row=5, column=0, columnspan=2, pady=5)
        
        # Rest of the method (doctor's appointments and general appointment list) remains the same
        if self.current_role == "doctor":
            tk.Label(self.root, text="My Appointments", font=("Arial", 12, "bold")).pack(pady=10)
            
            doctor_appt_frame = tk.Frame(self.root)
            doctor_appt_frame.pack(pady=10)
            
            self.doctor_appt_tree = ttk.Treeview(doctor_appt_frame, 
                                            columns=("ID", "Patient", "Date", "Time", "Status"), 
                                            show="headings")
            self.doctor_appt_tree.heading("ID", text="ID")
            self.doctor_appt_tree.heading("Patient", text="Patient")
            self.doctor_appt_tree.heading("Date", text="Date")
            self.doctor_appt_tree.heading("Time", text="Time")
            self.doctor_appt_tree.heading("Status", text="Status")
            self.doctor_appt_tree.pack()
            
            self.load_doctor_appointments()
            
            btn_frame = tk.Frame(self.root)
            btn_frame.pack(pady=5)
            ttk.Button(btn_frame, text="Complete Appointment", 
                    command=self.complete_appointment).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Cancel Appointment", 
                    command=self.cancel_appointment).pack(side=tk.LEFT, padx=5)
        
        tk.Label(self.root, text="All Appointments", font=("Arial", 12, "bold")).pack(pady=10)
        
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, columns=("ID", "Patient ID", "Doctor", "Date", "Time", "Status"), 
                        show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Patient ID", text="Patient ID")
        tree.heading("Doctor", text="Doctor")
        tree.heading("Date", text="Date")
        tree.heading("Time", text="Time")
        tree.heading("Status", text="Status")
        tree.pack(pady=5)
        
        cursor.execute("SELECT a.id, a.patient_id, e.full_name, a.date, a.time, a.status "
                    "FROM appointments a JOIN employees e ON a.doctor_id = e.id")
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)

    def populate_available_times(self, doctor_name, date, time_dropdown):
        if not all([doctor_name, date]):
            messagebox.showerror("Error", "Please select a doctor and date")
            return

        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Invalid date format (use YYYY-MM-DD)")
            return

        # Extract doctor_id
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM employees WHERE full_name LIKE ? AND role = 'doctor' AND status = 'approved'",
            (f"%{doctor_name.split(',')[0].replace('Dr. ', '')}%",)
        )
        doctor = cursor.fetchone()
        if not doctor:
            messagebox.showerror("Error", "Invalid doctor selected")
            return

        doctor_id = doctor[0]

        # Fetch schedules
        cursor.execute(
            """
            SELECT start_time, end_time FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? AND status = 'Available'
            """,
            (doctor_id, date)
        )
        schedules = cursor.fetchall()
        
        if not schedules:
            messagebox.showerror("Error", f"No available schedules for the selected doctor on {date}")
            time_dropdown["values"] = []
            return

        # Fetch booked times
        cursor.execute(
            """
            SELECT time FROM appointments 
            WHERE doctor_id = ? AND date = ? AND status = 'Scheduled'
            """,
            (doctor_id, date)
        )
        booked_times = [row[0] for row in cursor.fetchall()]

        # Generate available time slots
        available_slots = []
        for start_time, end_time in schedules:
            start_dt = datetime.strptime(f"{date} {start_time}", "%Y-%m-%d %H:%M")
            end_dt = datetime.strptime(f"{date} {end_time}", "%Y-%m-%d %H:%M")
            
            current_dt = start_dt
            while current_dt < end_dt:
                slot_time = current_dt.strftime("%H:%M")
                if slot_time not in booked_times:
                    available_slots.append(slot_time)
                current_dt += timedelta(minutes=30)

        if not available_slots:
            messagebox.showerror("Error", f"No available time slots for the selected doctor on {date}")
            time_dropdown["values"] = []
            return

        # Populate dropdown
        time_dropdown["values"] = available_slots
        if available_slots:
            time_dropdown.set(available_slots[0])  # Set default to first available slot

    def book_appointment(self, patient_id, doctor_name, date, time):
        if not all([patient_id, doctor_name, date, time]):
            messagebox.showerror("Error", "Please fill all fields")
            return

        # Validate patient ID and get name
        try:
            patient_id = int(patient_id)
            cursor = self.conn.cursor()
            cursor.execute("SELECT name FROM patients WHERE id = ?", (patient_id,))
            patient = cursor.fetchone()
            if not patient:
                messagebox.showerror("Error", f"Invalid patient ID: {patient_id}")
                return
            patient_name = patient[0]
        except ValueError:
            messagebox.showerror("Error", "Invalid patient ID format")
            return

        # Validate date and time
        try:
            datetime.strptime(date, "%Y-%m-%d")
            if not re.match(r"^\d{2}:\d{2}$", time):
                raise ValueError
            datetime.strptime(time, "%H:%M")
        except ValueError:
            messagebox.showerror("Error", "Invalid date (use YYYY-MM-DD) or time (use HH:MM) format")
            return

        # Extract doctor_id
        cursor.execute(
            "SELECT id FROM employees WHERE full_name LIKE ? AND role = 'doctor' AND status = 'approved'",
            (f"%{doctor_name.split(',')[0].replace('Dr. ', '')}%",)
        )
        doctor = cursor.fetchone()
        if not doctor:
            messagebox.showerror("Error", "Invalid doctor selected")
            return

        doctor_id = doctor[0]

        # Check doctor's schedule
        cursor.execute(
            """
            SELECT id FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? 
            AND start_time <= ? AND end_time >= ? 
            AND status = 'Available'
            """,
            (doctor_id, date, time, time)
        )
        schedule = cursor.fetchone()
        if not schedule:
            self.show_available_slots(doctor_id, date, patient_id, patient_name)
            return

        # Check for conflicting appointments
        cursor.execute(
            """
            SELECT id FROM appointments 
            WHERE doctor_id = ? AND date = ? AND time = ? AND status = 'Scheduled'
            """,
            (doctor_id, date, time)
        )
        if cursor.fetchone():
            messagebox.showerror(
                "Error", 
                f"Time slot {time} on {date} is already booked for patient ID: {patient_id} ({patient_name})"
            )
            self.show_available_slots(doctor_id, date, patient_id, patient_name)
            return

        # Book the appointment
        cursor.execute(
            """
            INSERT INTO appointments (patient_id, doctor_id, date, time, status) 
            VALUES (?, ?, ?, ?, ?)
            """,
            (patient_id, doctor_id, date, time, "Scheduled")
        )
        self.conn.commit()
        self.log_activity(f"Booked appointment for patient ID: {patient_id} ({patient_name}), doctor ID: {doctor_id}")
        messagebox.showinfo(
            "Success", 
            f"Appointment booked successfully for patient ID: {patient_id} ({patient_name}) at {time} on {date}"
        )
        self.appointment_scheduling()


    def load_doctor_appointments(self):
        """Load appointments for the current doctor user"""
        for item in self.doctor_appt_tree.get_children():
            self.doctor_appt_tree.delete(item)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT a.id, p.name, a.date, a.time, a.status 
            FROM appointments a 
            JOIN patients p ON a.patient_id = p.id 
            WHERE a.doctor_id = ? AND a.status = 'Scheduled'
            ORDER BY a.date, a.time
        """, (self.current_user_id,))
        
        for row in cursor.fetchall():
            self.doctor_appt_tree.insert("", tk.END, values=row)

    def complete_appointment(self):
        """Mark selected appointment as completed"""
        selected = self.doctor_appt_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an appointment")
            return
        
        appt_id = self.doctor_appt_tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        cursor.execute("UPDATE appointments SET status = 'Completed' WHERE id = ?", (appt_id,))
        self.conn.commit()
        self.log_activity(f"Completed appointment ID: {appt_id}")
        messagebox.showinfo("Success", "Appointment marked as completed")
        self.load_doctor_appointments()

    def cancel_appointment(self):
        """Cancel selected appointment"""
        selected = self.doctor_appt_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an appointment")
            return
        
        appt_id = self.doctor_appt_tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        cursor.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appt_id,))
        self.conn.commit()
        self.log_activity(f"Cancelled appointment ID: {appt_id}")
        messagebox.showinfo("Success", "Appointment cancelled")
        self.load_doctor_appointments()

    def prescription_management(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Prescription Management", font=("Arial", 14, "bold")).pack(pady=10)

        # Frame for prescription creation
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        # Patient ID and Name
        tk.Label(frame, text="Patient ID:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        patient_id_entry = tk.Entry(frame)
        patient_id_entry.grid(row=0, column=1, padx=5, pady=5)

        # Label to display patient name
        patient_name_label = tk.Label(frame, text="Patient Name: ", font=("Arial", 10))
        patient_name_label.grid(row=0, column=2, padx=5, pady=5)

        # Appointment ID
        tk.Label(frame, text="Appointment ID (Optional):", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        appointment_id_entry = tk.Entry(frame)
        appointment_id_entry.grid(row=1, column=1, padx=5, pady=5)

        # Function to validate patient ID and display name, and auto-select appointment
        def validate_patient_id(*args):
            patient_id = patient_id_entry.get()
            appointment_id_entry.delete(0, tk.END)  # Clear previous appointment ID
            if patient_id:
                try:
                    patient_id = int(patient_id)
                    cursor = self.conn.cursor()
                    cursor.execute("SELECT name FROM patients WHERE id = ?", (patient_id,))
                    patient = cursor.fetchone()
                    if patient:
                        patient_name_label.config(text=f"Patient Name: {patient[0]}")
                        # Auto-select the latest scheduled appointment for the patient
                        if self.current_role == "doctor":
                            cursor.execute("""
                                SELECT id FROM appointments 
                                WHERE patient_id = ? AND doctor_id = ? AND status = 'Scheduled'
                                ORDER BY date DESC, time DESC LIMIT 1
                            """, (patient_id, self.current_user_id))
                        else:
                            cursor.execute("""
                                SELECT id FROM appointments 
                                WHERE patient_id = ? AND status = 'Scheduled'
                                ORDER BY date DESC, time DESC LIMIT 1
                            """, (patient_id,))
                        appointment = cursor.fetchone()
                        if appointment:
                            appointment_id_entry.delete(0, tk.END)
                            appointment_id_entry.insert(0, str(appointment[0]))
                        else:
                            appointment_id_entry.delete(0, tk.END)
                            appointment_id_entry.insert(0, "")  # Clear if no appointment found
                            if self.current_role == "doctor":
                                patient_name_label.config(text=f"Patient Name: {patient[0]} (No scheduled appointments)")
                    else:
                        patient_name_label.config(text="Patient Name: Invalid ID")
                        appointment_id_entry.delete(0, tk.END)
                except (ValueError, TypeError):
                    patient_name_label.config(text="Patient Name: Invalid ID")
                    appointment_id_entry.delete(0, tk.END)
            else:
                patient_name_label.config(text="Patient Name: ")
                appointment_id_entry.delete(0, tk.END)

        # Bind validation to patient ID entry
        patient_id_entry.bind("<KeyRelease>", validate_patient_id)
        patient_id_entry.bind("<FocusOut>", validate_patient_id)

        # Symptoms
        tk.Label(frame, text="Symptoms:", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        symptoms_entry = tk.Text(frame, height=3, width=50)
        symptoms_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)

        # Diagnosis
        tk.Label(frame, text="Diagnosis:", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        diagnosis_entry = tk.Text(frame, height=3, width=50)
        diagnosis_entry.grid(row=3, column=1, columnspan=2, padx=5, pady=5)

        # Medications (dynamic entry fields)
        tk.Label(frame, text="Medications:", font=("Arial", 10, "bold")).grid(row=4, column=0, columnspan=3, pady=5)
        
        medication_frame = tk.Frame(frame)
        medication_frame.grid(row=5, column=0, columnspan=3, pady=5)
        
        medication_entries = []

        def add_medication_row():
            row_frame = tk.Frame(medication_frame)
            row_frame.pack(fill=tk.X, pady=2)
            tk.Label(row_frame, text="Medication Name").pack(side=tk.LEFT, padx=5)
            med_name = tk.Entry(row_frame, width=20)
            med_name.pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text="Dosage").pack(side=tk.LEFT, padx=5)
            dosage = tk.Entry(row_frame, width=15)
            dosage.pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text="Frequency").pack(side=tk.LEFT, padx=5)
            frequency = tk.Entry(row_frame, width=15)
            frequency.pack(side=tk.LEFT, padx=5)
            tk.Label(row_frame, text="Duration").pack(side=tk.LEFT, padx=5)
            duration = tk.Entry(row_frame, width=15)
            duration.pack(side=tk.LEFT, padx=5)
            medication_entries.append((row_frame, med_name, dosage, frequency, duration))
            
            # Add remove button for rows after the first one
            if len(medication_entries) > 1:
                ttk.Button(row_frame, text="Remove", command=lambda: remove_medication_row(row_frame)).pack(side=tk.LEFT, padx=5)

        def remove_medication_row(row_frame):
            medication_entries[:] = [(f, n, d, fr, du) for f, n, d, fr, du in medication_entries if f != row_frame]
            row_frame.destroy()

        # Add initial medication row
        add_medication_row()
        ttk.Button(frame, text="Add Another Medication", command=add_medication_row).grid(row=6, column=0, columnspan=3, pady=5)

        # Tests Recommended
        tk.Label(frame, text="Tests Recommended:", font=("Arial", 10)).grid(row=7, column=0, padx=5, pady=5)
        tests_entry = tk.Text(frame, height=3, width=50)
        tests_entry.grid(row=7, column=1, columnspan=2, padx=5, pady=5)

        # Doctor's Advice
        tk.Label(frame, text="Doctor's Advice:", font=("Arial", 10)).grid(row=8, column=0, padx=5, pady=5)
        advice_entry = tk.Text(frame, height=3, width=50)
        advice_entry.grid(row=8, column=1, columnspan=2, padx=5, pady=5)

        # Follow-up Date
        tk.Label(frame, text="Follow-up Date (YYYY-MM-DD):", font=("Arial", 10)).grid(row=9, column=0, padx=5, pady=5)
        followup_entry = tk.Entry(frame)
        followup_entry.grid(row=9, column=1, padx=5, pady=5)

        # Save Prescription Button
        ttk.Button(frame, text="Save Prescription", command=lambda: self.save_prescription(
            patient_id_entry.get(),
            appointment_id_entry.get(),
            symptoms_entry.get("1.0", tk.END).strip(),
            diagnosis_entry.get("1.0", tk.END).strip(),
            medication_entries,
            tests_entry.get("1.0", tk.END).strip(),
            advice_entry.get("1.0", tk.END).strip(),
            followup_entry.get()
        )).grid(row=10, column=0, columnspan=3, pady=10)

        # Prescription List
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        self.prescription_tree = ttk.Treeview(tree_frame, columns=("ID", "Patient ID", "Patient Name", "Date", "Diagnosis"), show="headings")
        self.prescription_tree.heading("ID", text="ID")
        self.prescription_tree.heading("Patient ID", text="Patient ID")
        self.prescription_tree.heading("Patient Name", text="Patient Name")
        self.prescription_tree.heading("Date", text="Date")
        self.prescription_tree.heading("Diagnosis", text="Diagnosis")
        self.prescription_tree.pack(pady=5)

        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)
        # Load prescriptions
        self.load_prescriptions()

        # Double-click to view prescription details
        self.prescription_tree.bind("<Double-1>", lambda e: self.view_prescription_details(self.prescription_tree))

    def view_prescription_details(self, tree):
        """
        Display detailed information about a selected prescription in a new window.
        
        Args:
            tree (ttk.Treeview): The Treeview widget containing the prescription list.
        """
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a prescription")
            return
        if len(selected) > 1:
            messagebox.showerror("Error", "Please select only one prescription at a time")
            return

        prescription_id = tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        
        try:
            # Fetch prescription details with patient and doctor information
            cursor.execute("""
                SELECT p.id, p.patient_id, p.doctor_id, p.appointment_id, p.symptoms, p.diagnosis,
                    p.medication, p.dosage, p.frequency, p.duration, p.instructions, p.tests,
                    p.followup_date, p.date, pat.name, pat.dob, pat.gender, e.full_name, e.specialty
                FROM prescriptions p
                JOIN patients pat ON p.patient_id = pat.id
                LEFT JOIN employees e ON p.doctor_id = e.id
                WHERE p.id = ?
            """, (prescription_id,))
            prescription = cursor.fetchone()
            
            if not prescription:
                messagebox.showerror("Error", "Prescription not found")
                return

            # Create details window
            details_window = tk.Toplevel(self.root)
            details_window.title(f"Prescription Details - ID {prescription_id}")
            details_window.geometry("700x700")

            # Add scrollable frame for content
            canvas = tk.Canvas(details_window)
            scrollbar = ttk.Scrollbar(details_window, orient="vertical", command=canvas.yview)
            scrollable_frame = tk.Frame(canvas)

            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )

            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Title
            tk.Label(scrollable_frame, text="Prescription Details", font=("Arial", 12, "bold")).pack(pady=10)

            # Extract data
            patient_id = prescription[1]
            patient_name = prescription[14]  # Correct index for patient name
            dob = prescription[15]  # Correct index for DOB
            gender = prescription[16]  # Correct index for gender
            prescription_date = prescription[13]  # Correct index for prescription date
            appointment_id = prescription[2] or "N/A"
            doctor_name = prescription[17] or "N/A"
            specialty = prescription[18] or "N/A"

            # Calculate age
            try:
                dob_date = datetime.strptime(dob, "%Y-%m-%d")
                age = (datetime.now() - dob_date).days // 365
            except (ValueError, TypeError):
                age = "Unknown"

            # Display patient info
            tk.Label(scrollable_frame, text=f"Patient Name: {patient_name}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Patient ID: {patient_id}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Age: {age}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Gender: {gender}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Date: {prescription_date}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Appointment ID: {appointment_id}", font=("Arial", 10)).pack(pady=5, anchor="w")

            # Display symptoms
            tk.Label(scrollable_frame, text="Symptoms:", font=("Arial", 10, "bold")).pack(pady=5, anchor="w")
            symptoms_text = tk.Text(scrollable_frame, height=3, width=60, wrap="word")
            symptoms_text.insert(tk.END, prescription[4] or "None")
            symptoms_text.config(state="disabled")
            symptoms_text.pack(pady=5, padx=10, anchor="w")

            # Display diagnosis
            tk.Label(scrollable_frame, text="Diagnosis:", font=("Arial", 10, "bold")).pack(pady=5, anchor="w")
            diagnosis_text = tk.Text(scrollable_frame, height=3, width=60, wrap="word")
            diagnosis_text.insert(tk.END, prescription[5] or "None")
            diagnosis_text.config(state="disabled")
            diagnosis_text.pack(pady=5, padx=10, anchor="w")

            # Display medications
            tk.Label(scrollable_frame, text="Medications:", font=("Arial", 10, "bold")).pack(pady=5, anchor="w")
            medications = prescription[6].split("\n") if prescription[6] else []
            if medications and medications[0]:
                for med in medications:
                    try:
                        name, dosage, frequency, duration = med.split("|")
                        tk.Label(scrollable_frame, 
                                text=f"{name}: {dosage}, {frequency}, for {duration}", 
                                font=("Arial", 10)).pack(pady=2, padx=20, anchor="w")
                    except ValueError:
                        tk.Label(scrollable_frame, 
                                text=f"Invalid medication format: {med}", 
                                font=("Arial", 10), fg="red").pack(pady=2, padx=20, anchor="w")
            else:
                tk.Label(scrollable_frame, text="None", font=("Arial", 10)).pack(pady=2, padx=20, anchor="w")

            # Display tests and advice
            tk.Label(scrollable_frame, text="Tests Recommended:", font=("Arial", 10, "bold")).pack(pady=5, anchor="w")
            tests_text = tk.Text(scrollable_frame, height=3, width=60, wrap="word")
            tests_text.insert(tk.END, prescription[11] or "None")  # Correct index for tests
            tests_text.config(state="disabled")
            tests_text.pack(pady=5, padx=10, anchor="w")

            tk.Label(scrollable_frame, text="Doctor's Advice:", font=("Arial", 10, "bold")).pack(pady=5, anchor="w")
            advice_text = tk.Text(scrollable_frame, height=3, width=60, wrap="word")
            advice_text.insert(tk.END, prescription[10] or "None")  # Correct index for instructions
            advice_text.config(state="disabled")
            advice_text.pack(pady=5, padx=10, anchor="w")

            tk.Label(scrollable_frame, text=f"Next Visit: {prescription[12] or 'Not specified'}", font=("Arial", 10)).pack(pady=5, anchor="w")
            tk.Label(scrollable_frame, text=f"Doctor: Dr. {doctor_name}, {specialty}", font=("Arial", 10)).pack(pady=5, anchor="w")

            # Download prescription slip button
            ttk.Button(scrollable_frame, text="Download Prescription Slip", 
                    command=lambda: self.generate_prescription_slip(
                        patient_id, patient_name, prescription[3], 
                        prescription[4], prescription[5], 
                        [m.split("|") for m in medications if m] if medications else [], 
                        prescription[11], prescription[10], prescription[12]
                    )).pack(pady=10)

            # Close button
            ttk.Button(scrollable_frame, text="Close", command=details_window.destroy).pack(pady=10)

        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load prescription details: {str(e)}")
            return

    def load_prescriptions(self):
        """Load prescriptions into the treeview"""
        for item in self.prescription_tree.get_children():
            self.prescription_tree.delete(item)
        
        cursor = self.conn.cursor()
        if self.current_role == "doctor":
            cursor.execute("""
                SELECT p.id, p.patient_id, pat.name, p.date, p.diagnosis
                FROM prescriptions p
                JOIN patients pat ON p.patient_id = pat.id
                WHERE p.doctor_id = ?
                ORDER BY p.date DESC
            """, (self.current_user_id,))
        else:
            cursor.execute("""
                SELECT p.id, p.patient_id, pat.name, p.date, p.diagnosis
                FROM prescriptions p
                JOIN patients pat ON p.patient_id = pat.id
                ORDER BY p.date DESC
            """)
        for row in cursor.fetchall():
            self.prescription_tree.insert("", tk.END, values=row)
    
    def save_prescription(self, patient_id, appointment_id, symptoms, diagnosis, medication_entries, tests, advice, followup):
        if appointment_id:
            try:
                appointment_id = int(appointment_id.split("ID: ")[1].split(" ")[0])
            except (ValueError, IndexError):
                appointment_id = None

        if not all([patient_id, symptoms, diagnosis]):
            messagebox.showerror("Error", "Patient ID, symptoms, and diagnosis are required")
            return

        # Validate patient ID
        try:
            patient_id = int(patient_id)
            cursor = self.conn.cursor()
            cursor.execute("SELECT name FROM patients WHERE id = ?", (patient_id,))
            patient = cursor.fetchone()
            if not patient:
                messagebox.showerror("Error", "Invalid patient ID")
                return
            patient_name = patient[0]
        except ValueError:
            messagebox.showerror("Error", "Invalid patient ID format")
            return

        # Validate appointment ID (required for doctors)
        if self.current_role == "doctor":
            appointment_id = int(appointment_id) if appointment_id else None
            cursor.execute("SELECT id, status FROM appointments WHERE id = ? AND patient_id = ? AND doctor_id = ? AND status = 'Scheduled'",
                        (appointment_id, patient_id, self.current_user_id))
        else:
            appointment_id = int(appointment_id) if appointment_id else None

        # Validate follow-up date
        if followup:
            try:
                followup_date = datetime.strptime(followup, "%Y-%m-%d")
                if followup_date.date() < datetime.now().date():
                    messagebox.showerror("Error", "Follow-up date must be in the future")
                    return
            except ValueError:
                messagebox.showerror("Error", "Invalid follow-up date format (use YYYY-MM-DD)")
                return

        # Collect medications
        medications = []
        for _, med_name, dosage, frequency, duration in medication_entries:
            med_name_val = med_name.get().strip()
            dosage_val = dosage.get().strip()
            frequency_val = frequency.get().strip()
            duration_val = duration.get().strip()
            if all([med_name_val, dosage_val, frequency_val, duration_val]):
                medications.append((med_name_val, dosage_val, frequency_val, duration_val))
            elif any([med_name_val, dosage_val, frequency_val, duration_val]):
                messagebox.showerror("Error", "Incomplete medication entry detected. Fill all fields or remove the row.")
                return
        
        if not medications:
            messagebox.showerror("Error", "At least one complete medication entry is required")
            return

        # Format medications for storage
        medication_str = "\n".join([f"{m[0]}|{m[1]}|{m[2]}|{m[3]}" for m in medications])

        try:
            cursor.execute("""
                INSERT INTO prescriptions (patient_id, doctor_id, appointment_id, symptoms, diagnosis, 
                    medication, dosage, frequency, duration, instructions, tests, followup_date, date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                patient_id,
                self.current_user_id if self.current_role == "doctor" else None,
                appointment_id,
                symptoms,
                diagnosis,
                medication_str,
                ";".join([m[1] for m in medications]),
                ";".join([m[2] for m in medications]),
                ";".join([m[3] for m in medications]),
                advice,
                tests,
                followup,
                datetime.now().strftime("%Y-%m-%d")
            ))
            self.conn.commit()
            self.log_activity(f"Created prescription for patient ID: {patient_id} ({patient_name})")
            
            # Generate LaTeX content for PDF
            latex_content = r"""
            \documentclass[a4paper,12pt]{article}
            \usepackage[utf8]{inputenc}
            \usepackage{geometry}
            \geometry{margin=1in}
            \usepackage{parskip}
            \usepackage{enumitem}
            \usepackage{titling}
            \setlength{\parindent}{0pt}
            \begin{document}
            
            \begin{center}
                \textbf{\Large Prescription Slip}
                \vspace{0.5cm}
                \hrulefill
            \end{center}
            
            \vspace{0.5cm}
            
            \textbf{Patient Name:} """ + patient_name + r""" \\
            \textbf{Patient ID:} """ + str(patient_id) + r""" \\
            \textbf{Appointment ID:} """ + (str(appointment_id) if appointment_id else "N/A") + r""" \\
            \textbf{Date:} """ + datetime.now().strftime("%Y-%m-%d") + r""" \\
            
            \vspace{0.5cm}
            
            \textbf{Symptoms:} \\
            """ + (symptoms.replace('\n', ' ') if symptoms else "Not specified") + r""" \\
            
            \vspace{0.3cm}
            
            \textbf{Diagnosis:} \\
            """ + (diagnosis.replace('\n', ' ') if diagnosis else "Not specified") + r""" \\
            
            \vspace{0.3cm}
            
            \textbf{Medications:}
            \begin{itemize}[leftmargin=*]
            """ + "".join([r"\item " + m[0] + ": " + m[1] + ", " + m[2] + ", Duration: " + m[3] for m in medications]) + r"""
            \end{itemize}
            
            \vspace{0.3cm}
            
            \textbf{Tests Recommended:} \\
            """ + (tests.replace('\n', ' ') if tests else "None") + r""" \\
            
            \vspace{0.3cm}
            
            \textbf{Doctor's Advice:} \\
            """ + (advice.replace('\n', ' ') if advice else "None") + r""" \\
            
            \vspace{0.3cm}
            
            \textbf{Follow-up Date:} """ + (followup if followup else "Not specified") + r""" \\
            
            \vspace{0.5cm}
            
            \textit{This is a computer-generated prescription. Please consult your healthcare provider for further details.}
            
            \end{document}
            """
            
            # Generate PDF filename using patient name and date
            sanitized_patient_name = "".join(c for c in patient_name if c.isalnum() or c == " ").replace(" ", "_")
            date_str = datetime.now().strftime("%Y%m%d")
            default_filename = f"{sanitized_patient_name}_{date_str}.tex"
            
            # Save LaTeX file
            filename = filedialog.asksaveasfilename(
                defaultextension=".tex",
                initialfile=default_filename,
                filetypes=[("LaTeX files", "*.tex"), ("All files", "*.*")],
                title="Save Prescription Slip"
            )
            if filename:
                try:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(latex_content)
                    messagebox.showinfo("Success", f"Prescription saved as LaTeX file: {filename}. Please compile it to generate a PDF.")
                    self.log_activity(f"Generated LaTeX prescription slip for patient ID: {patient_id} ({patient_name})")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save LaTeX file: {str(e)}")
            
            self.load_prescriptions()
            messagebox.showinfo("Success", "Prescription saved successfully")
            self.prescription_management()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to save prescription: {str(e)}")

    def generate_prescription_slip(self, patient_id, patient_name, appointment_id, symptoms, diagnosis, medications, tests, advice, followup):
        if not patient_name or not medications:
            messagebox.showerror("Error", "Patient name and medications are required")
            return

        # Prepare medication details
        med_details = "\n".join([f"- {m[0]}: {m[1]} ({m[2]}), Duration: {m[3]}" for m in medications])

        # Generate content for the prescription slip
        content = f"""Prescription Slip
            ------------------
            Patient Name: {patient_name}
            Patient ID: {patient_id}
            Appointment ID: {appointment_id if appointment_id else 'N/A'}
            Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Symptoms: {symptoms if symptoms else 'Not specified'}
            Diagnosis: {diagnosis if diagnosis else 'Not specified'}
            Medications:
            {med_details if med_details else 'None'}
            Tests Recommended: {tests if tests else 'None'}
            Doctor's Advice: {advice if advice else 'None'}
            Follow-up Date: {followup if followup else 'Not specified'}

            This is a computer-generated prescription. Please consult your healthcare provider for further details.
            """

        # Save to file
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Prescription Slip"
        )
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Prescription slip saved to {filename}")
                self.log_activity(f"Generated prescription slip for patient ID: {patient_id}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save prescription slip: {str(e)}")

    def employee_management(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Employee Management", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Filter for pending employees
        filter_frame = tk.Frame(self.root)
        filter_frame.pack(pady=5)
        filter_var = tk.BooleanVar()
        tk.Checkbutton(filter_frame, text="Show Pending Only", variable=filter_var,
                      command=lambda: self.filter_employees(tree, filter_var.get())).pack()
        
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        tk.Label(frame, text="Username:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        username_entry = tk.Entry(frame)
        username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Full Name:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        full_name_entry = tk.Entry(frame)
        full_name_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Email:", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        email_entry = tk.Entry(frame)
        email_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Phone:", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        phone_entry = tk.Entry(frame)
        phone_entry.grid(row=3, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Password:", font=("Arial", 10)).grid(row=4, column=0, padx=5, pady=5)
        password_entry = tk.Entry(frame, show="*")
        password_entry.grid(row=4, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Role:", font=("Arial", 10)).grid(row=5, column=0, padx=5, pady=5)
        role_var = tk.StringVar(value="staff")
        tk.Radiobutton(frame, text="Admin", variable=role_var, value="admin").grid(row=5, column=1, sticky="w")
        tk.Radiobutton(frame, text="Staff", variable=role_var, value="staff").grid(row=5, column=1)
        tk.Radiobutton(frame, text="Doctor", variable=role_var, value="doctor").grid(row=5, column=1, sticky="e")
        
        tk.Label(frame, text="Specialty (if Doctor):", font=("Arial", 10)).grid(row=6, column=0, padx=5, pady=5)
        specialty_entry = tk.Entry(frame)
        specialty_entry.grid(row=6, column=1, padx=5, pady=5)
        
        ttk.Button(frame, text="Add Employee", command=lambda: self.add_employee(
            username_entry.get(), full_name_entry.get(), email_entry.get(), 
            phone_entry.get(), password_entry.get(), role_var.get(), specialty_entry.get()
        )).grid(row=7, column=0, columnspan=2, pady=10)
        
        # Employee tree
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, columns=("ID", "Username", "Full Name", "Email", "Role", "Status", "Phone", "Specialty"), 
                           show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Username", text="Username")
        tree.heading("Full Name", text="Name")
        tree.heading("Email", text="Email")
        tree.heading("Role", text="Role")
        tree.heading("Status", text="Status")
        tree.heading("Phone", text="Phone")
        tree.heading("Specialty", text="Specialty")
        tree.pack(pady=5)
        
        self.filter_employees(tree, False)
        
        # Approve/Delete buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Approve Selected", command=lambda: self.approve_employee(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Selected", command=lambda: self.delete_employee(tree)).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)
    
    def filter_employees(self, tree, pending_only):
        for item in tree.get_children():
            tree.delete(item)
        cursor = self.conn.cursor()
        query = "SELECT id, username, full_name, email, role, status, phone, specialty FROM employees"
        if pending_only:
            query += " WHERE status = 'pending'"
        cursor.execute(query)
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
    
    def approve_employee(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an employee")
            return
        
        cursor = self.conn.cursor()
        for item in selected:
            emp_id = tree.item(item, "values")[0]
            cursor.execute("SELECT username, email FROM employees WHERE id = ?", (emp_id,))
            employee = cursor.fetchone()
            if not employee:
                messagebox.showerror("Error", f"Employee ID {emp_id} not found")
                continue
            
            username, email = employee
            cursor.execute("UPDATE employees SET status = 'approved' WHERE id = ?", (emp_id,))
            
            # Prepare email content
            try:
                # Create email message with username
                msg = MIMEText(
                    f"Dear {username},\n\n"
                    "Your account has been approved. You can now log in to the Healthcare System using the following credentials:\n\n"
                    f"Username: {username}\n\n"
                    f"Password: admin123\n\n"
                    "For security reasons, please use the password you set during registration or request a password reset if needed.\n\n"
                    "Best regards,\nHealthcare System Team"
                )
                msg['Subject'] = 'Account Approval'
                msg['From'] = 'sagorrobidush31@gmail.com'
                msg['To'] = email
                
                # Send email
                with smtplib.SMTP('smtp.gmail.com', 587) as server:
                    server.starttls()
                    server.login('sagorrobidush31@gmail.com', 'nggv lyxr zsgu zcue')  # Use environment variables for credentials
                    server.send_message(msg)
            except Exception as e:
                messagebox.showwarning("Email Error", f"Failed to send email to {email}: {str(e)}")
            
            self.log_activity(f"Approved employee ID: {emp_id}")
        
        self.conn.commit()
        messagebox.showinfo("Success", "Selected employees approved")
        self.employee_management()
    
    def delete_employee(self, tree):
        selected = tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an employee")
            return
        
        if messagebox.askyesno("Confirm", "Are you sure you want to delete selected employees?"):
            cursor = self.conn.cursor()
            for item in selected:
                emp_id = tree.item(item, "values")[0]
                cursor.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
                self.log_activity(f"Deleted employee ID: {emp_id}")
            self.conn.commit()
            messagebox.showinfo("Success", "Selected employees deleted")
            self.employee_management()
    
    def add_employee(self, username, full_name, email, phone, password, role, specialty):
        if not all([username, full_name, email, phone, password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format")
            return
        
        if not re.match(r"^\+?\d{10,15}$", phone):
            messagebox.showerror("Error", "Invalid phone number format")
            return
        
        if role == "doctor" and not specialty:
            messagebox.showerror("Error", "Specialty is required for doctors")
            return
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor = self.conn.cursor()
        try:
            cursor.execute("INSERT INTO employees (username, password, full_name, email, phone, role, specialty, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (username, hashed, full_name, email, phone, role, specialty, "approved"))
            self.conn.commit()
            self.log_activity(f"Added employee: {username}")
            messagebox.showinfo("Success", "Employee added successfully")
            self.employee_management()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
    
    
    def pharmacy_management(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Pharmacy Management", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Pharmacy Management Frame
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        # Medication Entry
        tk.Label(frame, text="Medication:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        medication_entry = tk.Entry(frame)
        medication_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Quantity Entry
        tk.Label(frame, text="Quantity:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = tk.Entry(frame)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Threshold Entry
        tk.Label(frame, text="Threshold:", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        threshold_entry = tk.Entry(frame)
        threshold_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Expiry Date Entry
        tk.Label(frame, text="Expiry Date (YYYY-MM-DD):", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        expiry_entry = tk.Entry(frame)
        expiry_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Supplier Selection
        tk.Label(frame, text="Supplier:", font=("Arial", 10)).grid(row=4, column=0, padx=5, pady=5)
        supplier_var = tk.StringVar()
        suppliers = ["Supplier A", "Supplier B", "Supplier C"]  # Example suppliers
        supplier_dropdown = ttk.Combobox(frame, textvariable=supplier_var, values=suppliers)
        supplier_dropdown.grid(row=4, column=1, padx=5, pady=5)
        
        # Action Buttons
        action_frame = tk.Frame(frame)
        action_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(action_frame, text="Update Stock", command=lambda: self.update_pharmacy(
            medication_entry.get(), quantity_entry.get(), threshold_entry.get(), expiry_entry.get()
        )).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Order Stock", command=lambda: self.order_stock_supplier(
            medication_entry.get(), quantity_entry.get(), supplier_var.get()
        )).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Return/Recall", command=lambda: self.return_recall_medication(
            medication_entry.get()
        )).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Sell Medicine", command=self.sell_medicine).pack(side=tk.LEFT, padx=5)
        
        # Pharmacy Inventory List
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        self.pharmacy_tree = ttk.Treeview(tree_frame, 
                                       columns=("ID", "Medication", "Quantity", "Threshold", "Expiry Date", "Status"), 
                                       show="headings")
        self.pharmacy_tree.heading("ID", text="ID")
        self.pharmacy_tree.heading("Medication", text="Medication")
        self.pharmacy_tree.heading("Quantity", text="Quantity")
        self.pharmacy_tree.heading("Threshold", text="Threshold")
        self.pharmacy_tree.heading("Expiry Date", text="Expiry Date")
        self.pharmacy_tree.heading("Status", text="Status")
        self.pharmacy_tree.pack(pady=5)
        
        # Bind double-click for editing
        self.pharmacy_tree.bind("<Double-1>", lambda e: self.edit_pharmacy_item(
            medication_entry, quantity_entry, threshold_entry, expiry_entry
        ))
        
        # Load pharmacy inventory
        self.load_pharmacy_inventory()
        
        # Check for low stock and expired medications
        self.check_stock_alerts()
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)
    
    def sell_medicine(self):
        """Open a new window to sell medicine from inventory"""
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Sell Medicine", font=("Arial", 14, "bold")).pack(pady=10)
        
        # Sell Medicine Frame
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        # Medication Selection
        tk.Label(frame, text="Medication:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        medication_var = tk.StringVar()
        cursor = self.conn.cursor()
        cursor.execute("SELECT medication FROM pharmacy WHERE status = 'Active'")
        medications = [row[0] for row in cursor.fetchall()]
        medication_dropdown = ttk.Combobox(frame, textvariable=medication_var, values=medications)
        medication_dropdown.grid(row=0, column=1, padx=5, pady=5)
        
        # Quantity Entry
        tk.Label(frame, text="Quantity to Sell:", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        quantity_entry = tk.Entry(frame)
        quantity_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Action Buttons
        action_frame = tk.Frame(frame)
        action_frame.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(action_frame, text="Sell", command=lambda: self.process_sale(
            medication_var.get(), quantity_entry.get()
        )).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Back", command=self.pharmacy_management).pack(side=tk.LEFT, padx=5)
        
        # Pharmacy Inventory List
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        self.pharmacy_tree = ttk.Treeview(tree_frame, 
                                       columns=("ID", "Medication", "Quantity", "Threshold", "Expiry Date", "Status"), 
                                       show="headings")
        self.pharmacy_tree.heading("ID", text="ID")
        self.pharmacy_tree.heading("Medication", text="Medication")
        self.pharmacy_tree.heading("Quantity", text="Quantity")
        self.pharmacy_tree.heading("Threshold", text="Threshold")
        self.pharmacy_tree.heading("Expiry Date", text="Expiry Date")
        self.pharmacy_tree.heading("Status", text="Status")
        self.pharmacy_tree.pack(pady=5)
        
        # Load pharmacy inventory
        self.load_pharmacy_inventory()
    
    def process_sale(self, medication, quantity):
        """Process the sale of a medication"""
        if not all([medication, quantity]):
            messagebox.showerror("Error", "Please select a medication and enter a quantity")
            return
        
        try:
            quantity = int(quantity)
            if quantity <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Quantity must be a positive number")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT quantity, expiry_date, status FROM pharmacy WHERE medication = ?", (medication,))
        result = cursor.fetchone()
        
        if not result:
            messagebox.showerror("Error", f"Medication {medication} not found in inventory")
            return
        
        current_quantity, expiry_date, status = result
        
        if status != "Active":
            messagebox.showerror("Error", f"Cannot sell {medication}: Status is {status}")
            return
        
        if expiry_date and datetime.strptime(expiry_date, "%Y-%m-%d").date() <= datetime.now().date():
            messagebox.showerror("Error", f"Cannot sell {medication}: Medication is expired")
            return
        
        if quantity > current_quantity:
            messagebox.showerror("Error", f"Insufficient stock for {medication}: Available {current_quantity}, Requested {quantity}")
            return
        
        # Update quantity
        new_quantity = current_quantity - quantity
        cursor.execute("UPDATE pharmacy SET quantity = ? WHERE medication = ?", (new_quantity, medication))
        self.conn.commit()
        
        # Log the sale
        self.log_activity(f"Sold {quantity} units of {medication}")
        messagebox.showinfo("Success", f"Sold {quantity} units of {medication}. New quantity: {new_quantity}")
        
        # Refresh inventory and check alerts
        self.load_pharmacy_inventory()
        self.check_stock_alerts()
    
    def load_pharmacy_inventory(self):
        """Load pharmacy inventory into the treeview"""
        for item in self.pharmacy_tree.get_children():
            self.pharmacy_tree.delete(item)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, medication, quantity, threshold, expiry_date, status FROM pharmacy")
        for row in cursor.fetchall():
            self.pharmacy_tree.insert("", tk.END, values=row)
    
    def edit_pharmacy_item(self, medication_entry, quantity_entry, threshold_entry, expiry_entry):
        """Populate entry fields with selected medication data for editing"""
        selected = self.pharmacy_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a medication to edit")
            return
        
        item = self.pharmacy_tree.item(selected[0], "values")
        medication_entry.delete(0, tk.END)
        medication_entry.insert(0, item[1])
        quantity_entry.delete(0, tk.END)
        quantity_entry.insert(0, item[2])
        threshold_entry.delete(0, tk.END)
        threshold_entry.insert(0, item[3])
        expiry_entry.delete(0, tk.END)
        expiry_entry.insert(0, item[4] if item[4] else "")
    
    def update_pharmacy(self, medication, quantity, threshold, expiry_date):
        """Update or add pharmacy stock with expiry date"""
        if not all([medication, quantity, threshold, expiry_date]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            quantity = int(quantity)
            threshold = int(threshold)
            if quantity < 0 or threshold < 0:
                raise ValueError
            datetime.strptime(expiry_date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Quantity and threshold must be positive numbers, and expiry date must be in YYYY-MM-DD format")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM pharmacy WHERE medication = ?", (medication,))
        existing = cursor.fetchone()
        
        status = "Active"
        if datetime.strptime(expiry_date, "%Y-%m-%d").date() <= datetime.now().date():
            status = "Expired"
        
        if existing:
            cursor.execute("UPDATE pharmacy SET quantity = ?, threshold = ?, expiry_date = ?, status = ? WHERE medication = ?",
                          (quantity, threshold, expiry_date, status, medication))
        else:
            cursor.execute("INSERT INTO pharmacy (medication, quantity, threshold, expiry_date, status) VALUES (?, ?, ?, ?, ?)",
                          (medication, quantity, threshold, expiry_date, status))
        self.conn.commit()
        self.log_activity(f"Updated pharmacy stock: {medication} (Qty: {quantity}, Expiry: {expiry_date})")
        messagebox.showinfo("Success", "Pharmacy stock updated")
        self.load_pharmacy_inventory()
        self.check_stock_alerts()
    
    def order_stock_supplier(self, medication, quantity, supplier):
        """Order new stock from supplier"""
        if not all([medication, quantity, supplier]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            quantity = int(quantity)
            if quantity <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Quantity must be a positive number")
            return
        
        # Simulate sending order to supplier
        order_details = f"Order for {quantity} units of {medication} from {supplier} on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Update pharmacy stock
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, quantity FROM pharmacy WHERE medication = ?", (medication,))
        existing = cursor.fetchone()
        
        if existing:
            new_quantity = existing[1] + quantity
            cursor.execute("UPDATE pharmacy SET quantity = ? WHERE medication = ?",
                          (new_quantity, medication))
        else:
            cursor.execute("INSERT INTO pharmacy (medication, quantity, threshold, expiry_date, status) VALUES (?, ?, ?, ?, ?)",
                          (medication, quantity, 10, (datetime.now() + timedelta(days=365)).strftime("%Y-%m-%d"), "Active"))
        
        self.conn.commit()
        self.log_activity(f"Ordered stock: {medication} (Qty: {quantity}) from {supplier}")
        messagebox.showinfo("Success", f"Order placed: {order_details}")
        self.load_pharmacy_inventory()
        self.check_stock_alerts()
    
    def return_recall_medication(self, medication):
        """Handle medication returns or recalls"""
        if not medication:
            messagebox.showerror("Error", "Please enter a medication name")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, quantity, expiry_date FROM pharmacy WHERE medication = ?", (medication,))
        existing = cursor.fetchone()
        
        if not existing:
            messagebox.showerror("Error", f"Medication {medication} not found in inventory")
            return
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to return/recall {medication}?"):
            cursor.execute("UPDATE pharmacy SET status = 'Recalled' WHERE medication = ?", (medication,))
            self.conn.commit()
            self.log_activity(f"Returned/Recalled medication: {medication}")
            messagebox.showinfo("Success", f"Medication {medication} marked as returned/recalled")
            self.load_pharmacy_inventory()
            self.check_stock_alerts()
    
    def check_stock_alerts(self):
        """Check for low stock and expired medications"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT medication, quantity, threshold, expiry_date FROM pharmacy WHERE quantity <= threshold OR (expiry_date <= ? AND status != 'Recalled')",
                      (datetime.now().strftime("%Y-%m-%d"),))
        alerts = cursor.fetchall()
        
        if alerts:
            alert_message = []
            for medication, quantity, threshold, expiry_date in alerts:
                if quantity <= threshold:
                    alert_message.append(f"Low stock alert: {medication} (Qty: {quantity}/{threshold})")
                if expiry_date and datetime.strptime(expiry_date, "%Y-%m-%d").date() <= datetime.now().date():
                    alert_message.append(f"Expired medication: {medication} (Expiry: {expiry_date})")
            if alert_message:
                messagebox.showwarning("Stock Alerts", "\n".join(alert_message))

    def view_doctor_info(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Doctor Information", font=("Arial", 14, "bold")).pack(pady=10)
        
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, 
                           columns=("ID", "Name", "Email", "Phone", "Specialty"), 
                           show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Name", text="Full Name")
        tree.heading("Email", text="Email")
        tree.heading("Phone", text="Phone")
        tree.heading("Specialty", text="Specialty")
        tree.pack(pady=5)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, full_name, email, phone, specialty FROM employees WHERE role = 'doctor' AND status = 'approved'")
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)
    
    def view_doctor_schedule(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="My Schedule", font=("Arial", 14, "bold")).pack(pady=10)
        
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, 
                           columns=("ID", "Date", "Start Time", "End Time", "Status"), 
                           show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Date", text="Date")
        tree.heading("Start Time", text="Start Time")
        tree.heading("End Time", text="End Time")
        tree.heading("Status", text="Status")
        tree.pack(pady=5)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, date, start_time, end_time, status FROM doctor_schedules WHERE doctor_id = ?",
                      (self.current_user_id,))
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)

    def doctor_schedule_management(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Doctor Schedule Management", font=("Arial", 14, "bold")).pack(pady=10)
        
        frame = tk.Frame(self.root)
        frame.pack(pady=10)
        
        # Schedule creation section
        tk.Label(frame, text="Doctor:", font=("Arial", 10)).grid(row=0, column=0, padx=5, pady=5)
        self.doctor_var = tk.StringVar()
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, full_name, specialty FROM employees WHERE role = 'doctor' AND status = 'approved'")
        doctors = [(row[0], f"Dr. {row[1]}, {row[2]}") for row in cursor.fetchall()]
        self.doctor_dropdown = ttk.Combobox(frame, textvariable=self.doctor_var, 
                                        values=[d[1] for d in doctors])
        self.doctor_dropdown.grid(row=0, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Date (YYYY-MM-DD):", font=("Arial", 10)).grid(row=1, column=0, padx=5, pady=5)
        self.date_entry = tk.Entry(frame)
        self.date_entry.grid(row=1, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Start Time (HH:MM):", font=("Arial", 10)).grid(row=2, column=0, padx=5, pady=5)
        self.start_time_entry = tk.Entry(frame)
        self.start_time_entry.grid(row=2, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="End Time (HH:MM):", font=("Arial", 10)).grid(row=3, column=0, padx=5, pady=5)
        self.end_time_entry = tk.Entry(frame)
        self.end_time_entry.grid(row=3, column=1, padx=5, pady=5)
        
        tk.Label(frame, text="Status:", font=("Arial", 10)).grid(row=4, column=0, padx=5, pady=5)
        self.status_var = tk.StringVar(value="Available")
        status_options = ["Available", "Unavailable", "On Leave"]
        ttk.Combobox(frame, textvariable=self.status_var, values=status_options).grid(row=4, column=1, padx=5, pady=5)
        
        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Add Schedule", command=self.add_doctor_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Update Schedule", command=self.update_doctor_schedule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Schedule", command=self.delete_doctor_schedule).pack(side=tk.LEFT, padx=5)
        
        # Schedule list with scrollbar
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.schedule_tree = ttk.Treeview(tree_frame, 
                                        columns=("ID", "Doctor", "Date", "Start Time", "End Time", "Status"), 
                                        show="headings",
                                        yscrollcommand=scroll_y.set)
        scroll_y.config(command=self.schedule_tree.yview)
        
        self.schedule_tree.heading("ID", text="ID")
        self.schedule_tree.heading("Doctor", text="Doctor")
        self.schedule_tree.heading("Date", text="Date")
        self.schedule_tree.heading("Start Time", text="Start Time")
        self.schedule_tree.heading("End Time", text="End Time")
        self.schedule_tree.heading("Status", text="Status")
        
        self.schedule_tree.column("ID", width=50)
        self.schedule_tree.column("Doctor", width=150)
        self.schedule_tree.column("Date", width=100)
        self.schedule_tree.column("Start Time", width=100)
        self.schedule_tree.column("End Time", width=100)
        self.schedule_tree.column("Status", width=100)
        
        self.schedule_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection event
        self.schedule_tree.bind("<<TreeviewSelect>>", self.on_schedule_select)
        
        # Load schedules
        self.load_doctor_schedules()
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)

    def load_doctor_schedules(self):
        """Load all doctor schedules into the treeview"""
        for item in self.schedule_tree.get_children():
            self.schedule_tree.delete(item)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT ds.id, e.full_name, ds.date, ds.start_time, ds.end_time, ds.status 
            FROM doctor_schedules ds 
            JOIN employees e ON ds.doctor_id = e.id
            ORDER BY ds.date, ds.start_time
        """)
        
        for row in cursor.fetchall():
            self.schedule_tree.insert("", tk.END, values=row)

    def on_schedule_select(self, event):
        """When a schedule is selected, populate the form fields"""
        selected = self.schedule_tree.selection()
        if not selected:
            return
        
        schedule_id = self.schedule_tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT ds.doctor_id, e.full_name, ds.date, ds.start_time, ds.end_time, ds.status 
            FROM doctor_schedules ds 
            JOIN employees e ON ds.doctor_id = e.id
            WHERE ds.id = ?
        """, (schedule_id,))
        
        schedule = cursor.fetchone()
        if schedule:
            doctor_id, doctor_name, date, start_time, end_time, status = schedule
            self.doctor_var.set(f"Dr. {doctor_name}")
            self.date_entry.delete(0, tk.END)
            self.date_entry.insert(0, date)
            self.start_time_entry.delete(0, tk.END)
            self.start_time_entry.insert(0, start_time)
            self.end_time_entry.delete(0, tk.END)
            self.end_time_entry.insert(0, end_time)
            self.status_var.set(status)

    def add_doctor_schedule(self):
        """Add a new doctor schedule"""
        doctor_name = self.doctor_var.get()
        date = self.date_entry.get()
        start_time = self.start_time_entry.get()
        end_time = self.end_time_entry.get()
        status = self.status_var.get()
        
        if not all([doctor_name, date, start_time, end_time, status]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        # Validate date format
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Invalid date format (use YYYY-MM-DD)")
            return
        
        # Validate time format
        try:
            datetime.strptime(start_time, "%H:%M")
            datetime.strptime(end_time, "%H:%M")
        except ValueError:
            messagebox.showerror("Error", "Invalid time format (use HH:MM)")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM employees WHERE full_name LIKE ? AND role = 'doctor'",
                    (f"%{doctor_name.split(',')[0].replace('Dr. ', '')}%",))
        doctor_id = cursor.fetchone()
        if not doctor_id:
            messagebox.showerror("Error", "Invalid doctor selected")
            return
        
        doctor_id = doctor_id[0]
        
        # Check for overlapping schedules
        cursor.execute("""
            SELECT id FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? 
            AND ((start_time <= ? AND end_time >= ?) OR 
                (start_time <= ? AND end_time >= ?) OR 
                (start_time >= ? AND end_time <= ?))
        """, (doctor_id, date, start_time, start_time, end_time, end_time, start_time, end_time))
        
        if cursor.fetchone():
            messagebox.showerror("Error", "Schedule overlaps with existing time slot")
            return
        
        cursor.execute("""
            INSERT INTO doctor_schedules (doctor_id, date, start_time, end_time, status) 
            VALUES (?, ?, ?, ?, ?)
        """, (doctor_id, date, start_time, end_time, status))
        
        self.conn.commit()
        self.log_activity(f"Added schedule for doctor ID: {doctor_id}")
        messagebox.showinfo("Success", "Schedule added successfully")
        self.load_doctor_schedules()

    def update_doctor_schedule(self):
        """Update selected doctor schedule"""
        selected = self.schedule_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a schedule to update")
            return
        
        schedule_id = self.schedule_tree.item(selected[0], "values")[0]
        doctor_name = self.doctor_var.get()
        date = self.date_entry.get()
        start_time = self.start_time_entry.get()
        end_time = self.end_time_entry.get()
        status = self.status_var.get()
        
        if not all([doctor_name, date, start_time, end_time, status]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM employees WHERE full_name LIKE ? AND role = 'doctor'",
                    (f"%{doctor_name.split(',')[0].replace('Dr. ', '')}%",))
        doctor_id = cursor.fetchone()
        if not doctor_id:
            messagebox.showerror("Error", "Invalid doctor selected")
            return
        
        doctor_id = doctor_id[0]
        
        # Check for overlapping schedules (excluding current schedule)
        cursor.execute("""
            SELECT id FROM doctor_schedules 
            WHERE doctor_id = ? AND date = ? AND id != ?
            AND ((start_time <= ? AND end_time >= ?) OR 
                (start_time <= ? AND end_time >= ?) OR 
                (start_time >= ? AND end_time <= ?))
        """, (doctor_id, date, schedule_id, start_time, start_time, end_time, end_time, start_time, end_time))
        
        if cursor.fetchone():
            messagebox.showerror("Error", "Schedule overlaps with existing time slot")
            return
        
        cursor.execute("""
            UPDATE doctor_schedules 
            SET doctor_id = ?, date = ?, start_time = ?, end_time = ?, status = ?
            WHERE id = ?
        """, (doctor_id, date, start_time, end_time, status, schedule_id))
        
        self.conn.commit()
        self.log_activity(f"Updated schedule ID: {schedule_id}")
        messagebox.showinfo("Success", "Schedule updated successfully")
        self.load_doctor_schedules()

    def delete_doctor_schedule(self):
        """Delete selected doctor schedule"""
        selected = self.schedule_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a schedule to delete")
            return
        
        if not messagebox.askyesno("Confirm", "Are you sure you want to delete this schedule?"):
            return
        
        schedule_id = self.schedule_tree.item(selected[0], "values")[0]
        cursor = self.conn.cursor()
        
        # Check if there are appointments for this schedule
        cursor.execute("""
            SELECT id FROM appointments 
            WHERE doctor_id = (SELECT doctor_id FROM doctor_schedules WHERE id = ?)
            AND date = (SELECT date FROM doctor_schedules WHERE id = ?)
            AND time BETWEEN (SELECT start_time FROM doctor_schedules WHERE id = ?) 
            AND (SELECT end_time FROM doctor_schedules WHERE id = ?)
            AND status = 'Scheduled'
        """, (schedule_id, schedule_id, schedule_id, schedule_id))
        
        if cursor.fetchone():
            messagebox.showerror("Error", "Cannot delete schedule with pending appointments")
            return
        
        cursor.execute("DELETE FROM doctor_schedules WHERE id = ?", (schedule_id,))
        self.conn.commit()
        self.log_activity(f"Deleted schedule ID: {schedule_id}")
        messagebox.showinfo("Success", "Schedule deleted successfully")
        self.load_doctor_schedules()


    def prescription_analytics(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Prescription Analytics", font=("Arial", 14, "bold")).pack(pady=10)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT medication, COUNT(*) as count FROM prescriptions WHERE doctor_id = ? GROUP BY medication",
                      (self.current_user_id,))
        analytics = cursor.fetchall()
        
        tk.Label(self.root, text="Medication Usage Statistics", font=("Arial", 12)).pack(pady=5)
        for med, count in analytics:
            tk.Label(self.root, text=f"{med}: {count} prescriptions").pack()
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)
    
    def view_activity_log(self):
        self.check_session_timeout()
        self.clear_window()
        tk.Label(self.root, text="Activity Log", font=("Arial", 14, "bold")).pack(pady=10)
        
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(pady=10)
        tree = ttk.Treeview(tree_frame, columns=("ID", "Username", "Action", "Timestamp"), show="headings")
        tree.heading("ID", text="ID")
        tree.heading("Username", text="Username")
        tree.heading("Action", text="Action")
        tree.heading("Timestamp", text="Timestamp")
        tree.pack(pady=5)
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM activity_log ORDER BY timestamp DESC")
        for row in cursor.fetchall():
            tree.insert("", tk.END, values=row)
        
        ttk.Button(self.root, text="Back", command=self.create_main_menu).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = HealthcareSystem(root)
    root.mainloop()
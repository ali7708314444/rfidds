import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import serial
import serial.tools.list_ports
import threading
import time
from datetime import datetime
import sqlite3
import hashlib
import json
import os
import sys

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('rfid_system.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # جدول المستخدمين (المشرفين والموظفين)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'employee')),
                full_name TEXT NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # جدول البطاقات
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_id TEXT UNIQUE NOT NULL,
                owner_name TEXT NOT NULL,
                details TEXT,
                password_hash TEXT,
                is_active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # جدول سجل الدخول والخروج
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                card_id TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                action_type TEXT NOT NULL, -- 'check_in' or 'check_out'
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (card_id) REFERENCES cards (card_id)
            )
        ''')
        
        # جدول سجل أنشطة المستخدمين
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # إضافة مستخدم افتراضي إذا لم يكن موجوداً
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        if cursor.fetchone()[0] == 0:
            default_password = self.hash_password("admin123")
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ("admin", default_password, "admin", "المشرف الرئيسي")
            )
        
        # إضافة موظف افتراضي إذا لم يكن موجوداً
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'employee'")
        if cursor.fetchone()[0] == 0:
            employee_password = self.hash_password("employee123")
            cursor.execute(
                "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                ("employee", employee_password, "employee", "موظف افتراضي")
            )
        
        self.conn.commit()
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_user(self, username, password):
        cursor = self.conn.cursor()
        password_hash = self.hash_password(password)
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1",
            (username, password_hash)
        )
        user = cursor.fetchone()
        return user
    
    def log_user_activity(self, username, activity_type, details=None):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO user_activity_logs (username, activity_type, details) VALUES (?, ?, ?)",
                (username, activity_type, details)
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error logging user activity: {e}")
            return False

    def add_card(self, card_id, owner_name, details, password=None):
        try:
            cursor = self.conn.cursor()
            password_hash = self.hash_password(password) if password else None
            cursor.execute(
                '''INSERT INTO cards (card_id, owner_name, details, password_hash) 
                   VALUES (?, ?, ?, ?)''',
                (card_id, owner_name, details, password_hash)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_card(self, card_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cards WHERE card_id = ?", (card_id,))
        return cursor.fetchone()
    
    def get_all_cards(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cards ORDER BY created_at DESC")
        return cursor.fetchall()
    
    def update_card(self, card_id, owner_name=None, details=None, password=None):
        try:
            cursor = self.conn.cursor()
            updates = []
            params = []
            
            if owner_name is not None:
                updates.append("owner_name = ?")
                params.append(owner_name)
            if details is not None:
                updates.append("details = ?")
                params.append(details)
            if password is not None:
                password_hash = self.hash_password(password)
                updates.append("password_hash = ?")
                params.append(password_hash)
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(card_id)
            
            query = f"UPDATE cards SET {', '.join(updates)} WHERE card_id = ?"
            cursor.execute(query, params)
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error updating card: {e}")
            return False
    
    def delete_card(self, card_id):
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM cards WHERE card_id = ?", (card_id,))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting card: {e}")
            return False
    
    def verify_card_password(self, card_id, password):
        card = self.get_card(card_id)
        if card and card[4]:  # password_hash موجود في العمود الرابع
            return self.hash_password(password) == card[4]
        return False
    
    def log_access(self, card_id, owner_name, action_type):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT INTO access_logs (card_id, owner_name, action_type) VALUES (?, ?, ?)",
                (card_id, owner_name, action_type)
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error logging access: {e}")
            return False
    
    def get_access_logs(self, card_id=None, limit=50):
        cursor = self.conn.cursor()
        if card_id:
            cursor.execute(
                '''SELECT * FROM access_logs 
                   WHERE card_id = ? 
                   ORDER BY timestamp DESC 
                   LIMIT ?''',
                (card_id, limit)
            )
        else:
            cursor.execute(
                '''SELECT * FROM access_logs 
                   ORDER BY timestamp DESC 
                   LIMIT ?''',
                (limit,)
            )
        return cursor.fetchall()
    
    def get_user_activity_logs(self, username=None, limit=50):
        cursor = self.conn.cursor()
        if username:
            cursor.execute(
                '''SELECT * FROM user_activity_logs 
                   WHERE username = ? 
                   ORDER BY timestamp DESC 
                   LIMIT ?''',
                (username, limit)
            )
        else:
            cursor.execute(
                '''SELECT * FROM user_activity_logs 
                   ORDER BY timestamp DESC 
                   LIMIT ?''',
                (limit,)
            )
        return cursor.fetchall()

class LoginWindow:
    def __init__(self, root, db):
        self.root = root
        self.db = db
        
        self.root.title("نظام إدارة RFID - تسجيل الدخول")
        self.root.geometry("400x350")
        self.root.resizable(False, False)
        self.center_window()
        
        self.create_widgets()
    
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # العنوان
        title_label = ttk.Label(main_frame, text="نظام إدارة RFID", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        subtitle_label = ttk.Label(main_frame, text="تسجيل الدخول", font=("Arial", 12))
        subtitle_label.pack(pady=5)
        
        # إطار الحقول
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=20, fill=tk.X)
        
        # اسم المستخدم
        ttk.Label(form_frame, text="اسم المستخدم:").grid(row=0, column=0, sticky=tk.W, pady=10)
        self.username_var = tk.StringVar()
        username_entry = ttk.Entry(form_frame, textvariable=self.username_var, width=25)
        username_entry.grid(row=0, column=1, sticky=tk.EW, pady=10, padx=(10, 0))
        
        # كلمة المرور
        ttk.Label(form_frame, text="كلمة المرور:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(form_frame, textvariable=self.password_var, show="*", width=25)
        password_entry.grid(row=1, column=1, sticky=tk.EW, pady=10, padx=(10, 0))
        
        # نوع المستخدم
        ttk.Label(form_frame, text="نوع الحساب:").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.user_type_var = tk.StringVar(value="employee")
        user_type_frame = ttk.Frame(form_frame)
        user_type_frame.grid(row=2, column=1, sticky=tk.EW, pady=10, padx=(10, 0))
        
        ttk.Radiobutton(user_type_frame, text="موظف", variable=self.user_type_var, value="employee").pack(side=tk.LEFT)
        ttk.Radiobutton(user_type_frame, text="مشرف", variable=self.user_type_var, value="admin").pack(side=tk.LEFT, padx=(10, 0))
        
        # زر تسجيل الدخول
        login_btn = ttk.Button(main_frame, text="تسجيل الدخول", command=self.login)
        login_btn.pack(pady=20)
        
        # معلومات الحسابات الافتراضية
        info_frame = ttk.LabelFrame(main_frame, text="الحسابات الافتراضية", padding="10")
        info_frame.pack(fill=tk.X, pady=10)
        
        info_text = """المشرف: 
اسم المستخدم: admin
كلمة المرور: admin123

الموظف:
اسم المستخدم: 123 
كلمة المرور: 123"""
        
        info_label = ttk.Label(info_frame, text=info_text, justify=tk.LEFT, font=("Arial", 9))
        info_label.pack()
        
        # إعداد تمديد الأعمدة
        form_frame.columnconfigure(1, weight=1)
        
        # جعل زر Enter ينشط تسجيل الدخول
        username_entry.bind('<Return>', lambda e: self.login())
        password_entry.bind('<Return>', lambda e: self.login())
    
    def login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        user_type = self.user_type_var.get()
        
        if not username or not password:
            messagebox.showerror("خطأ", "يرجى إدخال اسم المستخدم وكلمة المرور")
            return
        
        user = self.db.verify_user(username, password)
        
        if user:
            user_role = user[3]  # role في العمود الرابع
            if user_role != user_type:
                messagebox.showerror("خطأ", f"هذا المستخدم ليس {self.get_role_name(user_type)}")
                return
            
            # تسجيل نشاط الدخول
            self.db.log_user_activity(username, "login", f"تسجيل دخول كـ{self.get_role_name(user_role)}")
            
            # إغلاق نافذة التسجيل وفتح الواجهة الرئيسية
            self.root.destroy()
            self.open_main_system(user)
        else:
            messagebox.showerror("خطأ", "اسم المستخدم أو كلمة المرور غير صحيحة")
    
    def open_main_system(self, user):
        """فتح النظام الرئيسي"""
        root = tk.Tk()
        app = RFIDSystem(root, self.db, user)
        root.mainloop()
    
    def get_role_name(self, role):
        return "مشرف" if role == "admin" else "موظف"

class RFIDSystem:
    def __init__(self, root, db, user):
        self.root = root
        self.db = db
        self.user = user
        self.user_role = user[3]  # role في العمود الرابع
        
        self.root.title(f"نظام إدارة RFID المتكامل - {self.get_role_name(self.user_role)}")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # متغيرات النظام
        self.serial_connection = None
        self.is_reading = False
        self.checked_in_cards = set()  # تتبع البطاقات التي قامت بتسجيل الدخول
        
        # إنشاء واجهة المستخدم
        self.create_main_widgets()
        
        # محاولة الاتصال التلقائي بقارئ RFID
        if self.user_role == "admin":  # فقط المشرف يمكنه الاتصال
            self.auto_connect()
    
    def get_role_name(self, role):
        return "مشرف" if role == "admin" else "موظف"
    
    def create_main_widgets(self):
        """إنشاء الواجهة الرئيسية"""
        # إنشاء القوائم
        self.create_menu()
        
        # إنشاء الألسنة (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # لسان إدارة البطاقات (للمشرف فقط)
        if self.user_role == "admin":
            self.cards_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.cards_frame, text="إدارة البطاقات")
            self.create_cards_widgets()
        
        # لسان سجل الدخول والخروج
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="سجل الدخول والخروج")
        self.create_logs_widgets()
        
        # لسان سجل الأنشطة (للمشرف فقط)
        if self.user_role == "admin":
            self.activity_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.activity_frame, text="سجل الأنشطة")
            self.create_activity_widgets()
    
    def create_menu(self):
        """إنشاء قائمة النظام"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # قائمة النظام
        system_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="النظام", menu=system_menu)
        
        if self.user_role == "admin":
            system_menu.add_command(label="إدارة المستخدمين", command=self.manage_users)
            system_menu.add_separator()
        
        system_menu.add_command(label="تسجيل الخروج", command=self.logout)
        system_menu.add_separator()
        system_menu.add_command(label="خروج", command=self.quit_app)
    
    def create_cards_widgets(self):
        """إنشاء واجهة إدارة البطاقات (للمشرف فقط)"""
        # إطار الاتصال
        connection_frame = ttk.LabelFrame(self.cards_frame, text="إعدادات الاتصال", padding="10")
        connection_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(connection_frame, text="المنفذ:").grid(row=0, column=0, sticky=tk.W)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(connection_frame, textvariable=self.port_var)
        self.port_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(connection_frame, text="سرعة الاتصال:").grid(row=1, column=0, sticky=tk.W)
        self.baud_var = tk.StringVar(value="9600")
        baud_combo = ttk.Combobox(connection_frame, textvariable=self.baud_var, values=["9600", "115200", "57600", "38400"])
        baud_combo.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        btn_frame = ttk.Frame(connection_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.connect_btn = ttk.Button(btn_frame, text="اتصال", command=self.toggle_connection)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.refresh_btn = ttk.Button(btn_frame, text="تحديث المنافذ", command=self.refresh_ports)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # إطار قراءة البيانات
        data_frame = ttk.LabelFrame(self.cards_frame, text="بيانات RFID", padding="10")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.data_text = tk.Text(data_frame, height=10)
        scrollbar = ttk.Scrollbar(data_frame, orient=tk.VERTICAL, command=self.data_text.yview)
        self.data_text.configure(yscrollcommand=scrollbar.set)
        self.data_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # إطار تسجيل البطاقات
        register_frame = ttk.LabelFrame(self.cards_frame, text="تسجيل بطاقة جديدة", padding="10")
        register_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(register_frame, text="معرف البطاقة:").grid(row=0, column=0, sticky=tk.W)
        self.tag_id_var = tk.StringVar()
        tag_entry = ttk.Entry(register_frame, textvariable=self.tag_id_var)
        tag_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(register_frame, text="اسم الحامل:").grid(row=1, column=0, sticky=tk.W)
        self.owner_var = tk.StringVar()
        owner_entry = ttk.Entry(register_frame, textvariable=self.owner_var)
        owner_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(register_frame, text="التفاصيل:").grid(row=2, column=0, sticky=tk.W)
        self.details_var = tk.StringVar()
        details_entry = ttk.Entry(register_frame, textvariable=self.details_var)
        details_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(register_frame, text="كلمة المرور:").grid(row=3, column=0, sticky=tk.W)
        self.card_password_var = tk.StringVar()
        password_entry = ttk.Entry(register_frame, textvariable=self.card_password_var, show="*")
        password_entry.grid(row=3, column=1, sticky=(tk.W, tk.E))
        
        btn_frame2 = ttk.Frame(register_frame)
        btn_frame2.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Button(btn_frame2, text="تسجيل البطاقة", command=self.register_tag).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="تعديل البطاقة", command=self.edit_tag).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="حذف البطاقة", command=self.delete_tag).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame2, text="تعيين كلمة مرور", command=self.set_card_password).pack(side=tk.LEFT, padx=5)
        
        # إطار البطاقات المسجلة
        registered_frame = ttk.LabelFrame(self.cards_frame, text="البطاقات المسجلة", padding="10")
        registered_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("id", "card_id", "owner", "details", "created_at")
        self.tree = ttk.Treeview(registered_frame, columns=columns, show="headings", height=12)
        
        self.tree.heading("id", text="ID")
        self.tree.heading("card_id", text="معرف البطاقة")
        self.tree.heading("owner", text="اسم الحامل")
        self.tree.heading("details", text="التفاصيل")
        self.tree.heading("created_at", text="وقت التسجيل")
        
        self.tree.column("id", width=50)
        self.tree.column("card_id", width=150)
        self.tree.column("owner", width=150)
        self.tree.column("details", width=200)
        self.tree.column("created_at", width=150)
        
        tree_scroll = ttk.Scrollbar(registered_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # إعداد تمديد العناصر
        self.cards_frame.columnconfigure(0, weight=1)
        connection_frame.columnconfigure(1, weight=1)
        register_frame.columnconfigure(1, weight=1)
        registered_frame.columnconfigure(0, weight=1)
        registered_frame.rowconfigure(0, weight=1)
        
        # تحميل قائمة البطاقات
        self.refresh_cards_list()
    
    def create_logs_widgets(self):
        """إنشاء واجهة سجل الدخول والخروج"""
        # إطار التحكم
        control_frame = ttk.LabelFrame(self.logs_frame, text="التحكم في السجلات", padding="10")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="البطاقة:").grid(row=0, column=0, sticky=tk.W)
        self.filter_card_var = tk.StringVar()
        filter_card_combo = ttk.Combobox(control_frame, textvariable=self.filter_card_var)
        filter_card_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(control_frame, text="عدد السجلات:").grid(row=0, column=2, sticky=tk.W, padx=(20,0))
        self.log_limit_var = tk.StringVar(value="50")
        log_limit_spin = ttk.Spinbox(control_frame, from_=10, to=500, textvariable=self.log_limit_var)
        log_limit_spin.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        ttk.Button(control_frame, text="عرض السجلات", command=self.refresh_access_logs).grid(row=0, column=4, padx=5)
        
        if self.user_role == "admin":
            ttk.Button(control_frame, text="تصدير السجلات", command=self.export_logs).grid(row=0, column=5, padx=5)
        
        # إطار سجلات الدخول والخروج
        logs_frame = ttk.LabelFrame(self.logs_frame, text="سجلات الدخول والخروج", padding="10")
        logs_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("id", "card_id", "owner", "action", "timestamp")
        self.logs_tree = ttk.Treeview(logs_frame, columns=columns, show="headings", height=20)
        
        self.logs_tree.heading("id", text="ID")
        self.logs_tree.heading("card_id", text="معرف البطاقة")
        self.logs_tree.heading("owner", text="اسم الحامل")
        self.logs_tree.heading("action", text="الإجراء")
        self.logs_tree.heading("timestamp", text="الوقت")
        
        self.logs_tree.column("id", width=50)
        self.logs_tree.column("card_id", width=150)
        self.logs_tree.column("owner", width=150)
        self.logs_tree.column("action", width=100)
        self.logs_tree.column("timestamp", width=150)
        
        logs_scroll = ttk.Scrollbar(logs_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=logs_scroll.set)
        
        self.logs_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        logs_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # إعداد تمديد العناصر
        self.logs_frame.columnconfigure(0, weight=1)
        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(3, weight=1)
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)
        
        # تحديث قائمة البطاقات للتصفية
        self.update_filter_cards()
        self.refresh_access_logs()
    
    def create_activity_widgets(self):
        """إنشاء واجهة سجل الأنشطة (للمشرف فقط)"""
        # إطار التحكم
        control_frame = ttk.LabelFrame(self.activity_frame, text="التحكم في السجلات", padding="10")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="المستخدم:").grid(row=0, column=0, sticky=tk.W)
        self.filter_user_var = tk.StringVar()
        filter_user_combo = ttk.Combobox(control_frame, textvariable=self.filter_user_var)
        filter_user_combo.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(control_frame, text="عدد السجلات:").grid(row=0, column=2, sticky=tk.W, padx=(20,0))
        self.activity_limit_var = tk.StringVar(value="50")
        activity_limit_spin = ttk.Spinbox(control_frame, from_=10, to=500, textvariable=self.activity_limit_var)
        activity_limit_spin.grid(row=0, column=3, sticky=(tk.W, tk.E))
        
        ttk.Button(control_frame, text="عرض السجلات", command=self.refresh_activity_logs).grid(row=0, column=4, padx=5)
        ttk.Button(control_frame, text="تصدير السجلات", command=self.export_activity_logs).grid(row=0, column=5, padx=5)
        
        # إطار سجلات الأنشطة
        activity_frame = ttk.LabelFrame(self.activity_frame, text="سجلات أنشطة المستخدمين", padding="10")
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("id", "username", "activity_type", "details", "timestamp")
        self.activity_tree = ttk.Treeview(activity_frame, columns=columns, show="headings", height=20)
        
        self.activity_tree.heading("id", text="ID")
        self.activity_tree.heading("username", text="اسم المستخدم")
        self.activity_tree.heading("activity_type", text="نوع النشاط")
        self.activity_tree.heading("details", text="التفاصيل")
        self.activity_tree.heading("timestamp", text="الوقت")
        
        self.activity_tree.column("id", width=50)
        self.activity_tree.column("username", width=150)
        self.activity_tree.column("activity_type", width=150)
        self.activity_tree.column("details", width=250)
        self.activity_tree.column("timestamp", width=150)
        
        activity_scroll = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=activity_scroll.set)
        
        self.activity_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        activity_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # إعداد تمديد العناصر
        self.activity_frame.columnconfigure(0, weight=1)
        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(3, weight=1)
        activity_frame.columnconfigure(0, weight=1)
        activity_frame.rowconfigure(0, weight=1)
        
        # تحميل سجلات الأنشطة
        self.refresh_activity_logs()
        self.update_filter_users()
    
    def refresh_ports(self):
        """تحديث قائمة المنافذ المتاحة"""
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo['values'] = ports
        if ports and not self.port_var.get():
            self.port_var.set(ports[0])
    
    def auto_connect(self):
        """محاولة الاتصال التلقائي بقارئ RFID"""
        self.refresh_ports()
        
        # البحث عن منفذ قد يكون مرتبطًا بقارئ RFID
        for port in self.port_combo['values']:
            try:
                ser = serial.Serial(port, 9600, timeout=1)
                time.sleep(2)
                ser.write(b'\r\n')  # إرسال أمر لاختبار الاتصال
                response = ser.readline()
                if response:
                    self.port_var.set(port)
                    self.toggle_connection()
                    break
                ser.close()
            except:
                pass
    
    def toggle_connection(self):
        """تبديل حالة الاتصال"""
        if self.is_reading:
            self.stop_reading()
        else:
            self.start_reading()
    
    def start_reading(self):
        """بدء قراءة البيانات من قارئ RFID"""
        port = self.port_var.get()
        baudrate = int(self.baud_var.get())
        
        if not port:
            messagebox.showerror("خطأ", "يرجى اختيار منفذ اتصال")
            return
        
        try:
            self.serial_connection = serial.Serial(port, baudrate, timeout=1)
            self.is_reading = True
            self.connect_btn.config(text="إيقاف")
            self.data_text.insert(tk.END, f"تم الاتصال بقارئ RFID على المنفذ {port}\n")
            self.data_text.see(tk.END)
            
            # تسجيل النشاط
            self.db.log_user_activity(self.user[1], "rfid_connect", f"الاتصال بقارئ RFID على المنفذ {port}")
            
            # بدء خيط لقراءة البيانات
            self.reading_thread = threading.Thread(target=self.read_serial_data, daemon=True)
            self.reading_thread.start()
            
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في الاتصال: {str(e)}")
    
    def stop_reading(self):
        """إيقاف قراءة البيانات"""
        self.is_reading = False
        if self.serial_connection and self.serial_connection.is_open:
            self.serial_connection.close()
        self.connect_btn.config(text="اتصال")
        self.data_text.insert(tk.END, "تم قطع الاتصال بقارئ RFID\n")
        self.data_text.see(tk.END)
        
        # تسجيل النشاط
        self.db.log_user_activity(self.user[1], "rfid_disconnect", "قطع الاتصال بقارئ RFID")
    
    def read_serial_data(self):
        """قراءة البيانات من المنفذ التسلسلي"""
        while self.is_reading and self.serial_connection and self.serial_connection.is_open:
            try:
                if self.serial_connection.in_waiting > 0:
                    data = self.serial_connection.readline().decode('utf-8').strip()
                    if data:
                        self.process_rfid_data(data)
            except Exception as e:
                self.data_text.insert(tk.END, f"خطأ في القراءة: {str(e)}\n")
                self.data_text.see(tk.END)
                time.sleep(0.1)
    
    def process_rfid_data(self, data):
        """معالجة بيانات RFID المستلمة"""
        # عرض البيانات في واجهة المستخدم
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.data_text.insert(tk.END, f"[{timestamp}] {data}\n")
        self.data_text.see(tk.END)
        
        # محاولة استخراج معرف البطاقة من البيانات
        tag_id = self.extract_tag_id(data)
        if tag_id:
            self.tag_id_var.set(tag_id)
            self.handle_card_access(tag_id)
    
    def extract_tag_id(self, data):
        """استخراج معرف البطاقة من البيانات المستلمة"""
        # هذه الدالة تعتمد على تنسيق البيانات القادمة من القارئ
        # يمكن تعديلها حسب تنسيق البيانات الفعلي
        
        # مثال: إذا كانت البيانات تحتوي على معرف البطاقة فقط
        if len(data) >= 8 and all(c in '0123456789ABCDEF' for c in data.upper()):
            return data.upper()
        
        # مثال: إذا كانت البيانات تأتي بتنسيق معين مثل "TAG: 12345678"
        if "TAG:" in data.upper():
            parts = data.split()
            for part in parts:
                if len(part) >= 8 and all(c in '0123456789ABCDEF' for c in part.upper()):
                    return part.upper()
        
        return None
    
    def handle_card_access(self, card_id):
        """معالجة دخول/خروج البطاقة"""
        card = self.db.get_card(card_id)
        
        if not card:
            messagebox.showwarning("بطاقة غير مسجلة", f"البطاقة {card_id} غير مسجلة في النظام")
            return
        
        # التحقق مما إذا كانت البطاقة مفعلة
        if not card[5]:  # is_active في العمود السادس
            messagebox.showerror("بطاقة غير مفعلة", f"البطاقة {card_id} غير مفعلة")
            return
        
        # تحديد نوع الإجراء (دخول أو خروج)
        if card_id in self.checked_in_cards:
            # خروج
            action_type = "check_out"
            self.checked_in_cards.remove(card_id)
            message = f"تم تسجيل خروج: {card[2]}"
        else:
            # دخول
            action_type = "check_in"
            self.checked_in_cards.add(card_id)
            message = f"تم تسجيل دخول: {card[2]}"
        
        # تسجيل الإجراء في قاعدة البيانات
        self.db.log_access(card_id, card[2], action_type)
        
        # عرض الرسالة
        self.data_text.insert(tk.END, f"{message}\n")
        self.data_text.see(tk.END)
        
        # تحديث سجل الدخول والخروج
        self.refresh_access_logs()
        
        messagebox.showinfo("تمت العملية", message)
    
    def register_tag(self):
        """تسجيل بطاقة جديدة في النظام"""
        card_id = self.tag_id_var.get().strip().upper()
        owner = self.owner_var.get().strip()
        details = self.details_var.get().strip()
        password = self.card_password_var.get()
        
        if not card_id:
            messagebox.showerror("خطأ", "يرجى إدخال معرف البطاقة")
            return
        
        if not owner:
            messagebox.showerror("خطأ", "يرجى إدخال اسم حامل البطاقة")
            return
        
        if self.db.add_card(card_id, owner, details, password):
            messagebox.showinfo("نجاح", f"تم تسجيل البطاقة {card_id} بنجاح")
            self.refresh_cards_list()
            self.update_filter_cards()
            self.clear_form()
            
            # تسجيل النشاط
            self.db.log_user_activity(self.user[1], "card_register", f"تسجيل بطاقة جديدة: {card_id} - {owner}")
        else:
            messagebox.showerror("خطأ", "فشل في تسجيل البطاقة. قد تكون مسجلة مسبقاً")
    
    def edit_tag(self):
        """تعديل بيانات بطاقة موجودة"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("خطأ", "يرجى اختيار بطاقة للتعديل")
            return
        
        item = self.tree.item(selected[0])
        card_id = item['values'][1]  # معرف البطاقة في العمود الثاني
        
        # طلب كلمة المرور إذا كانت البطاقة محمية
        card = self.db.get_card(card_id)
        if card and card[4]:  # إذا كانت البطاقة لها كلمة مرور
            password = simpledialog.askstring("كلمة المرور", 
                                            f"أدخل كلمة مرور البطاقة {card_id}:",
                                            show='*')
            if not self.db.verify_card_password(card_id, password):
                messagebox.showerror("خطأ", "كلمة المرور غير صحيحة")
                return
        
        # فتح نافذة التعديل
        self.open_edit_dialog(card_id)
    
    def open_edit_dialog(self, card_id):
        """فتح نافذة تعديل البطاقة"""
        card = self.db.get_card(card_id)
        if not card:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"تعديل البطاقة {card_id}")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        
        ttk.Label(dialog, text="معرف البطاقة:").pack(pady=5)
        card_id_var = tk.StringVar(value=card_id)
        ttk.Entry(dialog, textvariable=card_id_var, state='readonly').pack(pady=5, fill=tk.X, padx=20)
        
        ttk.Label(dialog, text="اسم الحامل:").pack(pady=5)
        owner_var = tk.StringVar(value=card[2])
        ttk.Entry(dialog, textvariable=owner_var).pack(pady=5, fill=tk.X, padx=20)
        
        ttk.Label(dialog, text="التفاصيل:").pack(pady=5)
        details_var = tk.StringVar(value=card[3] if card[3] else "")
        ttk.Entry(dialog, textvariable=details_var).pack(pady=5, fill=tk.X, padx=20)
        
        ttk.Label(dialog, text="كلمة المرور الجديدة (اتركه فارغاً للحفاظ على القديمة):").pack(pady=5)
        password_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=password_var, show="*").pack(pady=5, fill=tk.X, padx=20)
        
        def save_changes():
            new_owner = owner_var.get().strip()
            new_details = details_var.get().strip()
            new_password = password_var.get() if password_var.get() else None
            
            if not new_owner:
                messagebox.showerror("خطأ", "يرجى إدخال اسم الحامل")
                return
            
            if self.db.update_card(card_id, new_owner, new_details, new_password):
                messagebox.showinfo("نجاح", "تم تحديث البطاقة بنجاح")
                self.refresh_cards_list()
                
                # تسجيل النشاط
                self.db.log_user_activity(self.user[1], "card_edit", f"تعديل بطاقة: {card_id}")
                
                dialog.destroy()
            else:
                messagebox.showerror("خطأ", "فشل في تحديث البطاقة")
        
        ttk.Button(dialog, text="حفظ التغييرات", command=save_changes).pack(pady=10)
    
    def delete_tag(self):
        """حذف بطاقة من النظام"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("خطأ", "يرجى اختيار بطاقة للحذف")
            return
        
        item = self.tree.item(selected[0])
        card_id = item['values'][1]
        owner = item['values'][2]
        
        # تأكيد الحذف
        if not messagebox.askyesno("تأكيد الحذف", f"هل أنت متأكد من حذف البطاقة {card_id} - {owner}؟"):
            return
        
        # طلب كلمة المرور إذا كانت البطاقة محمية
        card = self.db.get_card(card_id)
        if card and card[4]:  # إذا كانت البطاقة لها كلمة مرور
            password = simpledialog.askstring("كلمة المرور", 
                                            f"أدخل كلمة مرور البطاقة {card_id} للحذف:",
                                            show='*')
            if not self.db.verify_card_password(card_id, password):
                messagebox.showerror("خطأ", "كلمة المرور غير صحيحة")
                return
        
        if self.db.delete_card(card_id):
            messagebox.showinfo("نجاح", "تم حذف البطاقة بنجاح")
            self.refresh_cards_list()
            self.update_filter_cards()
            if card_id in self.checked_in_cards:
                self.checked_in_cards.remove(card_id)
            
            # تسجيل النشاط
            self.db.log_user_activity(self.user[1], "card_delete", f"حذف بطاقة: {card_id} - {owner}")
        else:
            messagebox.showerror("خطأ", "فشل في حذف البطاقة")
    
    def set_card_password(self):
        """تعيين كلمة مرور للبطاقة"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("خطأ", "يرجى اختيار بطاقة لتعيين كلمة المرور")
            return
        
        item = self.tree.item(selected[0])
        card_id = item['values'][1]
        
        password = simpledialog.askstring("كلمة المرور", 
                                        f"أدخل كلمة المرور الجديدة للبطاقة {card_id}:",
                                        show='*')
        if password:
            if self.db.update_card(card_id, password=password):
                messagebox.showinfo("نجاح", "تم تعيين كلمة المرور بنجاح")
                
                # تسجيل النشاط
                self.db.log_user_activity(self.user[1], "card_password_set", f"تعيين كلمة مرور للبطاقة: {card_id}")
            else:
                messagebox.showerror("خطأ", "فشل في تعيين كلمة المرور")
    
    def refresh_cards_list(self):
        """تحديث قائمة البطاقات"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        cards = self.db.get_all_cards()
        for card in cards:
            self.tree.insert("", tk.END, values=card)
    
    def update_filter_cards(self):
        """تحديث قائمة البطاقات للتصفية"""
        cards = self.db.get_all_cards()
        card_ids = [card[1] for card in cards]  # card_id في العمود الثاني
        self.filter_card_var.set('')
        # تحديث قائمة Combobox
        if self.user_role == "admin":
            filter_widget = self.logs_frame.winfo_children()[0].winfo_children()[1]  # الحصول على الـ Combobox
            filter_widget['values'] = [''] + card_ids
    
    def refresh_access_logs(self):
        """تحديث سجل الدخول والخروج"""
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        
        card_id = self.filter_card_var.get() if self.filter_card_var.get() else None
        limit = int(self.log_limit_var.get())
        
        logs = self.db.get_access_logs(card_id, limit)
        for log in logs:
            # تحويل action_type إلى نص عربي
            action_text = "دخول" if log[3] == "check_in" else "خروج"
            self.logs_tree.insert("", tk.END, values=(log[0], log[1], log[2], action_text, log[4]))
    
    def refresh_activity_logs(self):
        """تحديث سجل الأنشطة"""
        if self.user_role != "admin":
            return
            
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        
        username = self.filter_user_var.get() if self.filter_user_var.get() else None
        limit = int(self.activity_limit_var.get())
        
        logs = self.db.get_user_activity_logs(username, limit)
        for log in logs:
            self.activity_tree.insert("", tk.END, values=log)
    
    def update_filter_users(self):
        """تحديث قائمة المستخدمين للتصفية"""
        if self.user_role != "admin":
            return
            
        # الحصول على قائمة المستخدمين الفريدة من سجلات الأنشطة
        cursor = self.db.conn.cursor()
        cursor.execute("SELECT DISTINCT username FROM user_activity_logs ORDER BY username")
        users = [row[0] for row in cursor.fetchall()]
        
        self.filter_user_var.set('')
        filter_widget = self.activity_frame.winfo_children()[0].winfo_children()[1]  # الحصول على الـ Combobox
        filter_widget['values'] = [''] + users
    
    def export_logs(self):
        """تصدير السجلات إلى ملف"""
        try:
            card_id = self.filter_card_var.get() if self.filter_card_var.get() else None
            limit = int(self.log_limit_var.get())
            
            logs = self.db.get_access_logs(card_id, limit)
            
            filename = f"access_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ID,Card ID,Owner,Action,Timestamp\n")
                for log in logs:
                    action_text = "Check In" if log[3] == "check_in" else "Check Out"
                    f.write(f"{log[0]},{log[1]},{log[2]},{action_text},{log[4]}\n")
            
            messagebox.showinfo("نجاح", f"تم تصدير السجلات إلى {filename}")
            
            # تسجيل النشاط
            self.db.log_user_activity(self.user[1], "export_logs", f"تصدير سجلات الدخول والخروج إلى {filename}")
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في تصدير السجلات: {str(e)}")
    
    def export_activity_logs(self):
        """تصدير سجلات الأنشطة إلى ملف"""
        try:
            username = self.filter_user_var.get() if self.filter_user_var.get() else None
            limit = int(self.activity_limit_var.get())
            
            logs = self.db.get_user_activity_logs(username, limit)
            
            filename = f"activity_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("ID,Username,Activity Type,Details,Timestamp\n")
                for log in logs:
                    f.write(f"{log[0]},{log[1]},{log[2]},{log[3] if log[3] else ''},{log[4]}\n")
            
            messagebox.showinfo("نجاح", f"تم تصدير السجلات إلى {filename}")
            
            # تسجيل النشاط
            self.db.log_user_activity(self.user[1], "export_activity_logs", f"تصدير سجلات الأنشطة إلى {filename}")
        except Exception as e:
            messagebox.showerror("خطأ", f"فشل في تصدير السجلات: {str(e)}")
    
    def manage_users(self):
        """إدارة المستخدمين (للمشرف فقط)"""
        if self.user_role != "admin":
            messagebox.showerror("خطأ", "ليس لديك صلاحية للوصول إلى هذه الوظيفة")
            return
        
        # نافذة إدارة المستخدمين
        dialog = tk.Toplevel(self.root)
        dialog.title("إدارة المستخدمين")
        dialog.geometry("600x400")
        dialog.resizable(False, False)
        
        # إطار الإضافة
        add_frame = ttk.LabelFrame(dialog, text="إضافة مستخدم جديد", padding="10")
        add_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(add_frame, text="اسم المستخدم:").grid(row=0, column=0, sticky=tk.W)
        new_username_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=new_username_var).grid(row=0, column=1, sticky=tk.EW)
        
        ttk.Label(add_frame, text="كلمة المرور:").grid(row=1, column=0, sticky=tk.W)
        new_password_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=new_password_var, show="*").grid(row=1, column=1, sticky=tk.EW)
        
        ttk.Label(add_frame, text="الاسم الكامل:").grid(row=2, column=0, sticky=tk.W)
        new_fullname_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=new_fullname_var).grid(row=2, column=1, sticky=tk.EW)
        
        ttk.Label(add_frame, text="الدور:").grid(row=3, column=0, sticky=tk.W)
        new_role_var = tk.StringVar(value="employee")
        role_frame = ttk.Frame(add_frame)
        role_frame.grid(row=3, column=1, sticky=tk.EW)
        ttk.Radiobutton(role_frame, text="موظف", variable=new_role_var, value="employee").pack(side=tk.LEFT)
        ttk.Radiobutton(role_frame, text="مشرف", variable=new_role_var, value="admin").pack(side=tk.LEFT, padx=(10,0))
        
        def add_user():
            username = new_username_var.get().strip()
            password = new_password_var.get()
            fullname = new_fullname_var.get().strip()
            role = new_role_var.get()
            
            if not username or not password or not fullname:
                messagebox.showerror("خطأ", "يرجى ملء جميع الحقول")
                return
            
            try:
                cursor = self.db.conn.cursor()
                password_hash = self.db.hash_password(password)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role, full_name) VALUES (?, ?, ?, ?)",
                    (username, password_hash, role, fullname)
                )
                self.db.conn.commit()
                
                messagebox.showinfo("نجاح", "تم إضافة المستخدم بنجاح")
                refresh_users_list()
                
                # تسجيل النشاط
                self.db.log_user_activity(self.user[1], "user_add", f"إضافة مستخدم جديد: {username}")
                
                # تفريغ الحقول
                new_username_var.set("")
                new_password_var.set("")
                new_fullname_var.set("")
                
            except sqlite3.IntegrityError:
                messagebox.showerror("خطأ", "اسم المستخدم موجود مسبقاً")
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل في إضافة المستخدم: {str(e)}")
        
        ttk.Button(add_frame, text="إضافة مستخدم", command=add_user).grid(row=4, column=0, columnspan=2, pady=5)
        
        # إطار قائمة المستخدمين
        list_frame = ttk.LabelFrame(dialog, text="قائمة المستخدمين", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ("id", "username", "full_name", "role", "is_active")
        users_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=10)
        
        users_tree.heading("id", text="ID")
        users_tree.heading("username", text="اسم المستخدم")
        users_tree.heading("full_name", text="الاسم الكامل")
        users_tree.heading("role", text="الدور")
        users_tree.heading("is_active", text="مفعل")
        
        users_tree.column("id", width=50)
        users_tree.column("username", width=100)
        users_tree.column("full_name", width=150)
        users_tree.column("role", width=80)
        users_tree.column("is_active", width=60)
        
        tree_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=users_tree.yview)
        users_tree.configure(yscrollcommand=tree_scroll.set)
        
        users_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        def refresh_users_list():
            for item in users_tree.get_children():
                users_tree.delete(item)
            
            cursor = self.db.conn.cursor()
            cursor.execute("SELECT id, username, full_name, role, is_active FROM users ORDER BY id")
            users = cursor.fetchall()
            for user in users:
                users_tree.insert("", tk.END, values=user)
        
        def toggle_user_status():
            selected = users_tree.selection()
            if not selected:
                messagebox.showerror("خطأ", "يرجى اختيار مستخدم")
                return
            
            item = users_tree.item(selected[0])
            user_id = item['values'][0]
            username = item['values'][1]
            current_status = item['values'][4]
            new_status = not current_status
            
            try:
                cursor = self.db.conn.cursor()
                cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
                self.db.conn.commit()
                
                messagebox.showinfo("نجاح", f"تم {'تفعيل' if new_status else 'تعطيل'} المستخدم بنجاح")
                refresh_users_list()
                
                # تسجيل النشاط
                self.db.log_user_activity(self.user[1], "user_toggle", 
                                        f"{'تفعيل' if new_status else 'تعطيل'} المستخدم: {username}")
                
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل في تحديث حالة المستخدم: {str(e)}")
        
        # أزرار التحكم
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="تحديث القائمة", command=refresh_users_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="تفعيل/تعطيل", command=toggle_user_status).pack(side=tk.LEFT, padx=5)
        
        # إعداد تمديد العناصر
        add_frame.columnconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(0, weight=1)
        
        # تحميل قائمة المستخدمين
        refresh_users_list()
    
    def logout(self):
        """تسجيل خروج المستخدم"""
        # تسجيل نشاط الخروج
        self.db.log_user_activity(self.user[1], "logout", "تسجيل خروج")
        
        # إعادة تشغيل التطبيق
        self.root.destroy()
        restart_app()
    
    def quit_app(self):
        """إغلاق التطبيق"""
        self.root.quit()
        self.root.destroy()
    
    def clear_form(self):
        """تفريغ حقول النموذج"""
        self.owner_var.set("")
        self.details_var.set("")
        self.card_password_var.set("")

def restart_app():
    """إعادة تشغيل التطبيق"""
    python = sys.executable
    os.execl(python, python, *sys.argv)

def main():
    # انشاء نافذه تسجيل
    login_root = tk.Tk()
    db = Database()
    
    login_app = LoginWindow(login_root, db)
    login_root.mainloop()

if __name__ == "__main__":
    main()
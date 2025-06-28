
<h1 align="center"> Digital Healthcare System </h1>
<p align="center">
  <img src="https://github.com/nodeonline/nodejscart/actions/workflows/build.yml/badge.svg" alt="Github Action">
  <a href="https://twitter.com/evershopjs">
    <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/evershopjs?style=social">
  </a>
  <a href="https://discord.gg/GSzt7dt7RM">
    <img src="https://img.shields.io/discord/757179260417867879?label=discord" alt="Discord">
  </a>
  <a href="https://opensource.org/licenses/GPL-3.0">
    <img src="https://img.shields.io/badge/License-GPLv3-blue.svg" alt="License">
  </a>
</p>

<h2>Overview</h2>
<p align="left">The Digital Healthcare System is a comprehensive hospital management application built with Python and Tkinter for the GUI, SQLite for database storage, and various other libraries for additional functionality. This system provides modules for patient management, appointment scheduling, prescription management, pharmacy inventory, employee management, and activity logging.
</p>

## Features
<h3>1. User Authentication</h3>

- Role-based access control (Admin, Doctor, Staff)
- Secure password storage with bcrypt hashing
- Registration approval system
- Session timeout after 20 minutes of inactivity
- Password change functionality

### 2. Patient Management

- Complete patient records with:
  - Personal information
  - Medical history
  - Emergency contacts
  - Blood group and other vital details
- Search functionality
- Detailed patient view with appointment and prescription history
- Export prescription slips

### 3. Appointment Scheduling

- Doctor availability checking
- Time slot management
- Appointment status tracking (Scheduled, Completed, Cancelled)
- Reminders for upcoming appointments
- Doctor schedule management

### 4. Prescription Management
- Comprehensive prescription creation:
  - Symptoms and diagnosis
  - Multiple medications with dosage instructions
  - Tests recommended
  - Doctor's advice
  - Follow-up dates
- Prescription history tracking
- Export prescriptions to text files

### 5. Pharmacy Management

- Medication inventory tracking
- Stock level alerts
- Expiration date tracking
- Medication sales processing
- Supplier ordering system
- Return/recall functionality

### 6. Employee Management
- Admin approval for new registrations
- Role assignment (Admin, Doctor, Staff)
- Doctor specialty tracking
- Bulk operations (approve/delete multiple employees)

### 7. Reporting and Analytics

- Activity logging for all user actions
- Prescription analytics for doctors
- Appointment statistics

### 8. Additional Features

- Email notifications for account approvals
- CAPTCHA verification during registration
- Data validation for all inputs
- Responsive UI with scrollable sections where needed

## Database Schema

The system uses SQLite with the following tables:

1. __patients__ - Stores patient information
2. __appointments__ - Manages appointment scheduling
3. __prescriptions__- Contains prescription details
4. __employees__ - User accounts and roles
5. __pharmacy__ - Medication inventory
6. __activity_log__ - System activity tracking
7. __doctor_schedules__ - Doctor availability schedules



## Prerequisites

- Python 3.x
- Required Python libraries:
  - tkinter (usually included with Python)
  - bcrypt (pip install bcrypt)
  - smtplib (included with Python for email functionality)
- A LaTeX distribution (e.g., MiKTeX or TeX Live) for compiling<br> prescription PDFs.
- A Gmail account with an App Password for sending email<br> notifications (configure in approve_employee method).

## Installation

### Running the Application

1. Clone the repository
    ```bash
    git@github.com:shagorrobidas/digital-healthcare-system.git
    
2. Create Virtual Enviorement
     ```bash
     python3.x -m venv venv
   
3. Navigate to the project directory:
     ```bash
     cd digital-healthcare-system
     
4. Install the required Python libraries:
     ```bash
     pip install tkinter bcrypt smtplib
     
5. Run the main script:
     ```bash
     python healthcare_system.py

6. Use the default admin credentials to log in:
   - Username: **admin**
   - Password: admin123

## Usage Instructions

### Admin Users
- Can manage all system functions
- Approve new employee registrations
- View activity logs
- Manage all patient and appointment records

### Doctors
- Manage their own schedule
- Create and view prescriptions
- Access patient medical histories
- View prescription analytics

### Staff
- Manage patient records
- Schedule appointments
- Handle pharmacy operations

## Technical Details
###  Security Features
- Password hashing with bcrypt
- Input validation for all forms
- Session timeout
- Role-based access control
- Activity logging

### Email Configuration
> To enable email notifications for employee approvals:
1. Generate an App Password for your Gmail account:
   - Go to your Google Account settings > Security > 2-Step<br>Verification > App Passwords.
   - Create a new App Password for "Mail".
2. Update the approve_employee method in the code with your<br> Gmail email and App Password:
    ```bash
    server.login('your_email@gmail.com', 'your_app_password')



### Error Handling
- Comprehensive validation for all inputs
- Database error handling
- User-friendly error messages

## Contributing
> Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create a new branch (``git checkout -b feature/your-feature``).
3. Commit your changes (``git commit -m "Add your feature"``).
4. Push to the branch (``git push origin feature/your-feature``).
5. Open a Pull Request.


## Screenshots
Include screenshots of key interfaces here

## License
This project is licensed under the MIT License.

## Contact

For issues or suggestions, please open an issue on the GitHub repository or contact the maintainer at [ Mail](roysagor88@gmail.com) .

   

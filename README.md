# VeriSior

## Overview

This project aims to create a comprehensive Senior Citizen ID Verification System for District 5, Quezon City. Built with Django and PostgreSQL, VeriSior provides secure citizen registration, ID verification, discount tracking across multiple categories, and comprehensive records management. The system features enterprise-grade security with multi-factor authentication, role-based access control, and encrypted backup systems, catering to government offices and authorized establishments serving senior citizens.

## Instructions for Use

This system is provided strictly for academic demonstration, evaluation, and research purposes as part of a Capstone Project.

### Authorized Use
The following are permitted:
- System execution for evaluation, grading, and demonstration
- Code inspection for academic review and verification
- Local deployment for testing and assessment purposes only

The system is intended to be used by:
- Capstone advisers
- Panelists
- Authorized academic evaluators

### Restrictions
The following actions are strictly prohibited without explicit written consent from the author:
- Reuse or integration of any part of the source code into other academic projects
- Redistribution of the source code or system components
- Modification and redeployment for instructional, institutional, or commercial purposes
- Claiming authorship or partial ownership of the system or its components

Any use of this system beyond the scope of academic evaluation constitutes unauthorized use and may result in academic, institutional, and legal consequences.

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- pip (Python package manager)

### Installation Steps

1. **Install Python** if not already installed. You can download it from [python.org](https://python.org).

2. **Install PostgreSQL** if not already installed. Download from [postgresql.org](https://www.postgresql.org/download/).

3. **Clone or download** the project repository:

   ```bash
   git clone https://github.com/yourusername/verisior.git
   cd verisior
   ```

4. **Create a virtual environment** to isolate project dependencies. This step is optional but recommended:

   ```bash
   python -m venv verisior-venv
   ```

5. **Activate the virtual environment**:

   - On Windows:
     ```bash
     verisior-venv\Scripts\activate
     ```

   - On macOS and Linux:
     ```bash
     source verisior-venv/bin/activate
     ```

6. **Install the required dependencies** from the `requirements.txt` file:

   ```bash
   pip install -r requirements.txt
   ```

7. **Configure the database**:

   Create a PostgreSQL database and update the database settings in `settings.py` or create a `.env` file with your database credentials:

   ```
   DB_NAME=verisior_db
   DB_USER=your_username
   DB_PASSWORD=your_password
   DB_HOST=localhost
   DB_PORT=5432
   SECRET_KEY=your_secret_key
   ```

8. **Run database migrations**:

   ```bash
   python manage.py migrate
   ```

9. **Create a superuser account** for administrative access:

   ```bash
   python manage.py createsuperuser
   ```

10. **Load initial data** (if available):

    ```bash
    python manage.py loaddata initial_data.json
    ```

## Usage

1. **Navigate to the project directory** (if you haven't already):

   ```bash
   cd verisior
   ```

2. **Run the Django development server**:

   ```bash
   python manage.py runserver
   ```

3. **Access the platform** through your web browser at `http://127.0.0.1:8000/`.

4. **Login with your credentials**:
   - Admin users can access the full dashboard at `/admin/`
   - Staff and verifiers can access role-specific features
   - Public verification available at `/verify/`

## Features

- **Secure Registration & Authentication**: Multi-factor authentication with device fingerprinting
- **Senior Citizen Management**: Comprehensive lifecycle tracking with automated status updates
- **ID Verification System**: Real-time verification portal for establishments
- **Discount Tracking**: Multi-category discount monitoring and reporting
- **Role-Based Access Control**: Four user roles with 80+ granular permissions
- **Audit Logging**: Complete activity tracking for compliance
- **Encrypted Backups**: Automated secure backup system
- **Advanced Reporting**: Dashboard analytics with Chart.js integration
- **Batch Operations**: Bulk upload and processing capabilities
- **Content Management**: Public-facing CMS for announcements and policies

## Contact Information

For any inquiries or support, please contact:
- **System Author**: cedricgo.quantum@gmail.com

## Credits

This project was developed as a capstone thesis for STI College Novaliches by:

- **Cedric Go** (Lead Programmer / System Author) - System architecture, development, and implementation
- **Beatriz Mae Buan** (Project Manager) - Project documentation and coordination
- **Reece Roque** (System Analyst) - Requirements documentation and system analysis
- **Christian Joshua Garma** (Quality Assurance) - System testing and quality documentation

### Technologies Used

- **Backend**: Django 4.x, Python 3.x
- **Database**: PostgreSQL
- **Frontend**: Bootstrap 5, Chart.js...
- **Security**: Django-OTP, Cryptography...
- **Development**: VS Code, Git

## Ownership, Rights, and Legal Notice

This repository and all associated materials are the original intellectual property of the author.

© 2025 Cedric Go. All rights reserved.

Unauthorized reproduction, modification, redistribution, or use of this work beyond academic evaluation and grading constitutes a violation of intellectual property rights and academic integrity policies. Such violations may result in institutional disciplinary action and/or legal consequences under applicable laws.

Access to this repository does not grant ownership, authorship, or usage rights beyond those explicitly stated.

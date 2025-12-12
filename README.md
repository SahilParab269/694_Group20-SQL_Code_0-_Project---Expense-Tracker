# 694_Group20-SQL_Code_0-_Project---Expense-Tracker

# Application Setup Instructions

## Prerequisites

Ensure the following tools are installed on your system:

1) Node.js (v16 or later recommended)
   
2) npm (comes with Node.js)

3) Docker & Docker Desktop
   
4) Git
   
5) A modern web browser (Chrome, Firefox, Edge)

## Clone the Repository

git clone 'given-github-repo-url' cd 'project-folder-name'

## Install Backend Dependencies

Go to 'backend' folder , open the command prompt and run:

npm install

This installs all required Node.js packages defined in package.json in the backend folder.

## Set Up PostgreSQL Using Docker

The application uses PostgreSQL running inside a Docker container.

docker pull postgres

docker run --name DBMS_Project -p 5403:5432 -e POSTGRES_PASSWORD=sqlcode0 -d postgres:14.8

Verify the container is running:

docker ps

## Initialize the Database

Connect to PostgreSQL and run the SQL scripts provided in 'tables_defn.txt' file to create schema and tables.

## Start the Backend Server

Go to the 'backend' folder , open the command prompt and run:

node app.js

You should see a confirmation message indicating the server is running.

## Access the Application (as the User)

Go to the 'frontend' folder , and execute 'index.html' to start with the login page or 'signup.html' to start with the signup page.

## Admin Access (Optional)

Need to insert Admin login credentials through backend insert query.

There is no sign-up option for admin users.

## Access the Application (as the Admin)

Go to the 'frontend' folder , and execute 'admin1.html' to start with the login page for the admin.

## Fix for serial sequence issue for 'expense_id' in 'expense_records table' (Optional)

In case of direct insert query to the 'expense_records' table to populate the test/demo data -

Go to the 'backend' folder , open the command prompt and run:

node seq_fix.js

You should see a confirmation message that the sequence issue is fixed. Might need to run this ad-hoc script every time there is backend insert into the table through query.

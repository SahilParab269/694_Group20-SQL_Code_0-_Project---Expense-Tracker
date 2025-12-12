const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const pool = require('./db');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ------------------------
// Helper: Standard Response
// ------------------------
function sendResponse(res, success, message, extra = {}) {
  res.json({ success, message, ...extra });
}

// ------------------------
// VALIDATION FUNCTIONS
// ------------------------
function validateSignup({ username, email, phone, password }) {

  if (!username || username.length < 3)
    return "Username must be at least 3 characters long.";

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email))
    return "Invalid email format.";

  const phoneRegex = /^[0-9]{10}$/;
  if (!phone || !phoneRegex.test(phone))
    return "Phone must be 10 digits.";

  if (!password || password.length < 6)
    return "Password must be at least 6 characters.";

  return null;
}

// ------------------------
// LOGIN ENDPOINT
// ------------------------
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return sendResponse(res, false, "Username and password required");

  try {
    const customerQuery = `
      SELECT customer_id 
      FROM expense_tracker.customer_details 
      WHERE username = $1;
    `;
    const customerResult = await pool.query(customerQuery, [username]);

    if (customerResult.rows.length === 0)
      return sendResponse(res, false, "Invalid username or password");

    const customer_id = customerResult.rows[0].customer_id;

    const loginQuery = `
      SELECT pass_word_hash 
      FROM expense_tracker.customer_login 
      WHERE customer_id = $1;
    `;
    const loginResult = await pool.query(loginQuery, [customer_id]);
    if (loginResult.rows.length === 0)
      return sendResponse(res, false, "Invalid username or password");

    const hash = loginResult.rows[0].pass_word_hash;
    const match = await bcrypt.compare(password, hash);

    if (!match)
      return sendResponse(res, false, "Invalid username or password");

    await pool.query(
      "UPDATE expense_tracker.customer_login SET last_login = NOW() WHERE customer_id = $1",
      [customer_id]
    );

    // Return only customer_id
    return sendResponse(res, true, "Login successful", { customer_id });

  } catch (err) {
    console.error("Login error:", err);
    return sendResponse(res, false, "Database error", {
      pg_code: err.code,
      pg_detail: err.detail
    });
  }
});

// ------------------------
// SIGNUP ENDPOINT
// ------------------------
app.post("/signup", async (req, res) => {
  try {
    const { username, email, phone, password } = req.body;

    // 1. Validate input
    const validationError = validateSignup({ username, email, phone, password });
    if (validationError) return sendResponse(res, false, validationError);

    // 2. Check for duplicates
    const dupQuery = `
      SELECT username, email 
      FROM expense_tracker.customer_details 
      WHERE username = $1 OR email = $2;
    `;
    const dupResult = await pool.query(dupQuery, [username, email]);

    if (dupResult.rows.length > 0) {
      const existing = dupResult.rows[0];
      if (existing.username === username)
        return sendResponse(res, false, "Username already exists.");
      if (existing.email === email)
        return sendResponse(res, false, "Email already exists.");
    }

    // 3. Password hashing
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Generate new customer_id
    const idResult = await pool.query(
      "SELECT COALESCE(MAX(customer_id), 0) + 1 AS new_id FROM expense_tracker.customer_details"
    );
    const customer_id = idResult.rows[0].new_id;

    // 5. Insert into customer_details
    await pool.query(
      `INSERT INTO expense_tracker.customer_details 
       (customer_id, username, email, phone)
       VALUES ($1, $2, $3, $4)`,
      [customer_id, username, email, phone]
    );

    // 6. Insert into customer_login
    await pool.query(
      `INSERT INTO expense_tracker.customer_login 
       (customer_id, pass_word_hash)
       VALUES ($1, $2)`,
      [customer_id, hashedPassword]
    );

    // 7. Insert default "Miscellaneous" category
    await pool.query(
      `INSERT INTO expense_tracker.expense_category 
       (customer_id, expense_name)
       VALUES ($1, $2)`,
      [customer_id, "Miscellaneous"]
    );

    return sendResponse(res, true, "Sign up successful. You can log in now.");

  } catch (err) {
    console.error("Signup error:", err);

    return sendResponse(res, false, "Signup failed", {
      pg_code: err.code,
      pg_detail: err.detail,
      constraint: err.constraint
    });
  }
});

// ------------------------
// DASHBOARD: Get Categories
// ------------------------
app.post("/dashboard/categories", async (req, res) => {
    try {
        const { customer_id } = req.body;
        if (!customer_id) return sendResponse(res, false, "customer_id required");

        const result = await pool.query(
            "SELECT expense_name FROM expense_tracker.expense_category WHERE customer_id = $1 ORDER BY expense_name",
            [customer_id]
        );
        return sendResponse(res, true, "Categories fetched", { categories: result.rows });
    } catch (err) {
        console.error(err);
        return sendResponse(res, false, "Database error fetching categories");
    }
});

// ------------------------
// DASHBOARD: Get Expenses (USD only)
// ------------------------
app.post("/dashboard/expenses", async (req, res) => {
    try {
        const { customer_id, startDate, endDate, month, category, last30Days } = req.body;
        if (!customer_id) return sendResponse(res, false, "customer_id required");

        let conditions = ["r.customer_id = $1"];
        let values = [customer_id];
        let idx = 2;

        if (last30Days && !startDate && !endDate && !month && !category) {
            conditions.push(`r.expense_date >= NOW() - INTERVAL '30 days'`);
        }

        if (startDate) {
            conditions.push(`r.expense_date >= $${idx}`);
            values.push(startDate);
            idx++;
        }
        if (endDate) {
            conditions.push(`r.expense_date <= $${idx}`);
            values.push(endDate);
            idx++;
        }
        if (month) {
            conditions.push(`TO_CHAR(r.expense_date, 'YYYY-MM') = $${idx}`);
            values.push(month);
            idx++;
        }
        if (category) {
            conditions.push(`r.expense_name = $${idx}`);
            values.push(category);
            idx++;
        }

        const whereClause = conditions.length ? "WHERE " + conditions.join(" AND ") : "";

        const query = `
            SELECT r.expense_id, r.expense_name, r.expense_date, r.expense_comment,
                   t.USD_amount AS amount
            FROM expense_tracker.expense_records r
            JOIN expense_tracker.expense_transaction t ON r.expense_id = t.expense_id
            ${whereClause}
            ORDER BY r.expense_date DESC
        `;

        const result = await pool.query(query, values);

        const expenses = result.rows.map(row => ({
            expense_id: row.expense_id,
            expense_name: row.expense_name,
            expense_date: row.expense_date,
            expense_comment: row.expense_comment,
            amount: parseFloat(row.amount)
        }));

        return sendResponse(res, true, "Expenses fetched", { expenses });

    } catch (err) {
        console.error(err);
        return sendResponse(res, false, "Database error fetching expenses");
    }
});

// ------------------------
// DASHBOARD: Add New Expense
// ------------------------
app.post("/dashboard/add_expense", async (req, res) => {
  try {
    const { customer_id, expense_name, expense_date, expense_comment, usd_amount } = req.body;
    if (!customer_id || !expense_name || !expense_date || usd_amount === undefined)
      return sendResponse(res, false, "Missing required fields");

    const recordResult = await pool.query(
      `INSERT INTO expense_tracker.expense_records
       (customer_id, expense_name, expense_date, expense_comment)
       VALUES ($1, $2, $3, $4)
       RETURNING expense_id`,
      [customer_id, expense_name, expense_date, expense_comment || ""]
    );

    const expense_id = recordResult.rows[0].expense_id;

    await pool.query(
      `INSERT INTO expense_tracker.expense_transaction
       (expense_id, USD_amount, INR_amount, EUR_amount)
       VALUES ($1, $2, $3, $4)`,
      [expense_id, usd_amount, 0.00, 0.00]
    );

    return sendResponse(res, true, "Expense added successfully");

  } catch (err) {
    console.error("Add Expense Error:", err);
    return sendResponse(res, false, "Failed to add expense", { pg_code: err.code, pg_detail: err.detail });
  }
});

// ------------------------
// DASHBOARD: Add New Expense Category
// ------------------------
app.post("/dashboard/add_category", async (req, res) => {
    try {
        const { customer_id, expense_name } = req.body;
        if (!customer_id || !expense_name) 
            return sendResponse(res, false, "Customer ID and category name are required");

        const checkQuery = `
            SELECT 1 
            FROM expense_tracker.expense_category 
            WHERE customer_id = $1 AND LOWER(expense_name) = LOWER($2)
        `;
        const checkResult = await pool.query(checkQuery, [customer_id, expense_name.trim()]);
        if (checkResult.rows.length > 0) {
            return sendResponse(res, false, "Category already exists");
        }

        const insertQuery = `
            INSERT INTO expense_tracker.expense_category (customer_id, expense_name)
            VALUES ($1, $2)
        `;
        await pool.query(insertQuery, [customer_id, expense_name.trim()]);

        return sendResponse(res, true, "Category added successfully");

    } catch (err) {
        console.error("Add Category Error:", err);
        return sendResponse(res, false, "Failed to add category", { pg_code: err.code, pg_detail: err.detail });
    }
});

// ---------------------------
// Fetch profile
// ---------------------------
app.post("/profile", async (req,res)=>{
    try{
        const { customer_id } = req.body;
        const result = await pool.query(
            `SELECT username, email, phone FROM expense_tracker.customer_details WHERE customer_id=$1`,
            [customer_id]
        );
        if(result.rows.length === 0) return res.json({ success:false, message:"Profile not found" });
        return res.json({ success:true, profile: result.rows[0] });
    }catch(err){
        console.error(err);
        return res.json({ success:false, message:"Error fetching profile" });
    }
});

// ---------------------------
// Update profile
// ---------------------------
app.post("/profile/update", async (req,res)=>{
    try{
        const { customer_id, username, phone, password } = req.body;

        await pool.query('BEGIN');

        await pool.query(
            `UPDATE expense_tracker.customer_details
             SET username=$1, phone=$2
             WHERE customer_id=$3`,
            [username, phone, customer_id]
        );

        if(password && password.trim() !== ""){
            const hashed = await bcrypt.hash(password, 10);
            await pool.query(
                `UPDATE expense_tracker.customer_login
                 SET pass_word_hash=$1
                 WHERE customer_id=$2`,
                 [hashed, customer_id]
            );
        }

        await pool.query('COMMIT');
        return res.json({ success:true, message:"Profile updated successfully" });
    }catch(err){
        await pool.query('ROLLBACK');
        console.error(err);
        return res.json({ success:false, message:"Error updating profile" });
    }
});

// ------------------------
// DASHBOARD: Analytics - Pie and Daily
// ------------------------
app.post("/dashboard/analytics/pie", async (req, res) => {
  try {
    const { customer_id, startDate, endDate, month } = req.body;
    if (!customer_id) return sendResponse(res, false, "customer_id required");

    let conditions = ["r.customer_id = $1"];
    const values = [customer_id];
    let idx = 2;

    if (startDate) {
      conditions.push(`r.expense_date >= $${idx}`);
      values.push(startDate);
      idx++;
    }
    if (endDate) {
      conditions.push(`r.expense_date <= $${idx}`);
      values.push(endDate);
      idx++;
    }
    if (month) {
      conditions.push(`TO_CHAR(r.expense_date, 'YYYY-MM') = $${idx}`);
      values.push(month);
      idx++;
    }

    const whereClause = conditions.length ? "WHERE " + conditions.join(" AND ") : "";

    const query = `
      SELECT r.expense_name,
             COALESCE(SUM(t.USD_amount),0)::numeric(12,2) AS total_usd
      FROM expense_tracker.expense_records r
      JOIN expense_tracker.expense_transaction t ON r.expense_id = t.expense_id
      ${whereClause}
      GROUP BY r.expense_name
      ORDER BY total_usd DESC
    `;

    const result = await pool.query(query, values);

    const data = result.rows.map(r => ({
      category: r.expense_name,
      total: parseFloat(r.total_usd)
    }));

    return sendResponse(res, true, "Pie data fetched", { data });
  } catch (err) {
    console.error("Analytics Pie Error:", err);
    return sendResponse(res, false, "Database error fetching pie data", { pg_code: err.code, pg_detail: err.detail });
  }
});

app.post("/dashboard/analytics/daily", async (req, res) => {
  try {
    const { customer_id, month } = req.body;
    if (!customer_id) return sendResponse(res, false, "customer_id required");
    if (!month) return sendResponse(res, false, "month (YYYY-MM) required");

    const query = `
      SELECT r.expense_date::date AS expense_date,
             r.expense_name,
             COALESCE(SUM(t.USD_amount),0)::numeric(12,2) AS total_usd
      FROM expense_tracker.expense_records r
      JOIN expense_tracker.expense_transaction t ON r.expense_id = t.expense_id
      WHERE r.customer_id = $1
        AND TO_CHAR(r.expense_date, 'YYYY-MM') = $2
      GROUP BY expense_date, r.expense_name
      ORDER BY expense_date
    `;

    const result = await pool.query(query, [customer_id, month]);

    const rows = result.rows.map(r => ({
      date: r.expense_date,
      category: r.expense_name,
      amount: parseFloat(r.total_usd)
    }));

    return sendResponse(res, true, "Daily analytics fetched", { rows });
  } catch (err) {
    console.error("Analytics Daily Error:", err);
    return sendResponse(res, false, "Database error fetching daily data", { pg_code: err.code, pg_detail: err.detail });
  }
});

// ------------------------
// Delete Expense (UPDATED)
// ------------------------
app.post("/dashboard/delete_expense", async (req,res)=>{
    try{
        const customer_id = parseInt(req.body.customer_id);
        const expense_id = parseInt(req.body.expense_id);

        if(!customer_id || !expense_id)
            return res.json({ success:false, message:"Missing required fields" });

        await pool.query('BEGIN');

        await pool.query(
            "DELETE FROM expense_tracker.expense_transaction WHERE expense_id=$1",
            [expense_id]
        );

        const delResult = await pool.query(
            "DELETE FROM expense_tracker.expense_records WHERE expense_id=$1 AND customer_id=$2",
            [expense_id, customer_id]
        );

        await pool.query('COMMIT');

        if(delResult.rowCount === 0)
            return res.json({ success:false, message:"Expense not found or already deleted" });

        return res.json({ success:true, message:"Expense deleted successfully" });
    }catch(err){
        await pool.query('ROLLBACK');
        console.error("Delete Expense Error:", err);
        return res.json({ success:false, message:"Error deleting expense", pg_code: err.code, pg_detail: err.detail });
    }
});

// ------------------------
// Update Expense
// ------------------------
app.post("/dashboard/update_expense", async (req,res)=>{
    try{
        const { customer_id, expense_id, expense_name, expense_date, expense_comment, usd_amount } = req.body;
        if(!customer_id || !expense_id || !expense_name || !expense_date || usd_amount === undefined)
            return res.json({ success:false, message:"Missing required fields" });

        await pool.query('BEGIN');

        await pool.query(
            `UPDATE expense_tracker.expense_records
             SET expense_name=$1, expense_date=$2, expense_comment=$3
             WHERE expense_id=$4 AND customer_id=$5`,
            [expense_name, expense_date, expense_comment || "", expense_id, customer_id]
        );

        await pool.query(
            `UPDATE expense_tracker.expense_transaction
             SET USD_amount=$1
             WHERE expense_id=$2`,
            [usd_amount, expense_id]
        );

        await pool.query('COMMIT');
        return res.json({ success:true, message:"Expense updated successfully" });
    }catch(err){
        await pool.query('ROLLBACK');
        console.error("Update Expense Error:", err);
        return res.json({ success:false, message:"Error updating expense", pg_code: err.code, pg_detail: err.detail });
    }
});


// ------------------------
// ADMIN LOGIN ENDPOINT
// ------------------------
app.post("/admin/login", async (req, res) => {
  const { admin_id, admin_pass } = req.body;

  if (!admin_id || !admin_pass) {
    return sendResponse(res, false, "Admin ID and password required");
  }

  try {
    const query = `
      SELECT admin_pass 
      FROM expense_tracker.admin_details
      WHERE admin_id = $1
    `;

    const result = await pool.query(query, [admin_id]);

    if (result.rows.length === 0) {
      return sendResponse(res, false, "Invalid Admin ID or password");
    }

    const storedPass = result.rows[0].admin_pass;

    // No encryption check — compare plain text
    if (storedPass !== admin_pass) {
      return sendResponse(res, false, "Invalid Admin ID or password");
    }

    // Login success
    return sendResponse(res, true, "Admin login successful", { admin_id });

  } catch (err) {
    console.error("Admin Login Error:", err);
    return sendResponse(res, false, "Database error during admin login", {
      pg_code: err.code,
      pg_detail: err.detail
    });
  }
});

// ------------------------
// ADMIN CHANGE PASSWORD
// ------------------------
app.post("/admin/change_password", async (req, res) => {
    const { admin_id, currentPwd, newPwd } = req.body;

    if(!admin_id || !currentPwd || !newPwd){
        return res.json({ success:false, message:"All fields are required" });
    }

    try {
        const query = `
            SELECT admin_pass 
            FROM expense_tracker.admin_details
            WHERE admin_id = $1
        `;
        const result = await pool.query(query, [admin_id]);

        if(result.rows.length === 0){
            return res.json({ success:false, message:"Admin not found" });
        }

        const storedPass = result.rows[0].admin_pass;

        if(storedPass !== currentPwd){
            return res.json({ success:false, message:"Current password is incorrect" });
        }

        await pool.query(
            `UPDATE expense_tracker.admin_details
             SET admin_pass = $1
             WHERE admin_id = $2`,
            [newPwd, admin_id]
        );

        return res.json({ success:true, message:"Password updated successfully" });

    } catch(err){
        console.error("Admin Change Password Error:", err);
        return res.json({ success:false, message:"Database error", pg_code: err.code, pg_detail: err.detail });
    }
});

// ------------------------
// ADMIN DASHBOARD STATS (Counts & Totals)
// ------------------------
app.post("/admin/dashboard/stats", async (req,res)=>{
    try{
        const { admin_id } = req.body;
        if(!admin_id) return res.json({ success:false, message:"Admin ID required" });

        // 1️⃣ Update admin_daily_count table
        const today = new Date().toISOString().split('T')[0];

        const userCountResult = await pool.query(`SELECT COUNT(*) AS total_users FROM expense_tracker.customer_details`);
        const totalUsers = parseInt(userCountResult.rows[0].total_users);

        const expenseCountResult = await pool.query(`SELECT COUNT(*) AS total_expenses FROM expense_tracker.expense_records`);
        const totalExpenses = parseInt(expenseCountResult.rows[0].total_expenses);

        const dailyExists = await pool.query(`SELECT 1 FROM expense_tracker.admin_daily_count WHERE date_count=$1`, [today]);
        if(dailyExists.rows.length === 0){
            await pool.query(`INSERT INTO expense_tracker.admin_daily_count(date_count, count_customers, count_expenses) VALUES($1,$2,$3)`,
                [today, totalUsers, totalExpenses]);
        } else {
            await pool.query(`UPDATE expense_tracker.admin_daily_count SET count_customers=$1, count_expenses=$2 WHERE date_count=$3`,
                [totalUsers, totalExpenses, today]);
        }

        // 2️⃣ Total expense categories
        const catResult = await pool.query(`SELECT COUNT(*) AS total_categories FROM expense_tracker.expense_category`);
        const totalCategories = parseInt(catResult.rows[0].total_categories);

        // 3️⃣ Total expenses & amount
        const amountResult = await pool.query(`SELECT COALESCE(SUM(t.USD_amount),0) AS total_amount FROM expense_tracker.expense_transaction t`);
        const totalAmount = parseFloat(amountResult.rows[0].total_amount);

        // Available years for bar chart
        const yearRes = await pool.query(`SELECT DISTINCT EXTRACT(YEAR FROM expense_date) AS year FROM expense_tracker.expense_records ORDER BY year`);
        const available_years = yearRes.rows.map(r=>r.year);

        return res.json({
            success:true,
            daily_count: totalUsers,
            total_categories: totalCategories,
            total_expenses: totalExpenses,
            total_amount: totalAmount,
            available_years
        });

    }catch(err){
        console.error(err);
        return res.json({ success:false, message:"Error fetching stats", pg_code:err.code, pg_detail:err.detail });
    }
});

// ------------------------
// LINE CHART: Expenses trend per month
// ------------------------
app.post("/admin/dashboard/analytics/line", async (req,res)=>{
    try{
        const { month } = req.body; // YYYY-MM

        const query = `
            SELECT expense_date::date AS date, COALESCE(SUM(t.USD_amount),0) AS total
            FROM expense_tracker.expense_records r
            JOIN expense_tracker.expense_transaction t ON r.expense_id=t.expense_id
            WHERE TO_CHAR(expense_date,'YYYY-MM')=$1
            GROUP BY expense_date
            ORDER BY expense_date
        `;
        const result = await pool.query(query, [month]);

        const labels = result.rows.map(r => r.date.toISOString().split('T')[0]);
        const values = result.rows.map(r => parseFloat(r.total));

        return res.json({ success:true, labels, values });

    }catch(err){
        console.error(err);
        return res.json({ success:false, message:"Error fetching line chart data", pg_code:err.code, pg_detail:err.detail });
    }
});

// ------------------------
// BAR CHART: Monthly total & counts per year
// ------------------------
app.post("/admin/dashboard/analytics/bar", async (req,res)=>{
    try{
        const { year } = req.body;

        const query = `
            SELECT EXTRACT(MONTH FROM expense_date) AS month, 
                   COUNT(*) AS count_expenses,
                   COALESCE(SUM(t.USD_amount),0) AS total_amount
            FROM expense_tracker.expense_records r
            JOIN expense_tracker.expense_transaction t ON r.expense_id=t.expense_id
            WHERE EXTRACT(YEAR FROM expense_date) = $1
            GROUP BY month
            ORDER BY month
        `;
        const result = await pool.query(query, [year]);

        const labels = result.rows.map(r => r.month);
        const counts = result.rows.map(r => parseInt(r.count_expenses));
        const amounts = result.rows.map(r => parseFloat(r.total_amount));

        return res.json({ success:true, labels, counts, amounts });

    }catch(err){
        console.error(err);
        return res.json({ success:false, message:"Error fetching bar chart data", pg_code:err.code, pg_detail:err.detail });
    }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

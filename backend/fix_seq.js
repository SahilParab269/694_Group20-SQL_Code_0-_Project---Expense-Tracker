import pool from "./db.js";

async function fixExpenseIdSequence() {
  const sql = `
    SELECT setval(
      'expense_tracker.expense_records_expense_id_seq',
      (SELECT COALESCE(MAX(expense_id), 0) FROM expense_tracker.expense_records) + 1,
      false
    );
  `;

  try {
    await pool.query(sql);
    console.log("Sequence fixed successfully.");
  } catch (err) {
    console.error("Error fixing sequence:", err);
  } finally {
    pool.end();
  }
}

fixExpenseIdSequence();

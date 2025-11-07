// app.js - Main entry point for the Node.js Express server
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const crypto = require('crypto'); // For password reset tokens
const nodemailer = require('nodemailer'); // For sending reset emails (configure with your SMTP)
const app = express();
const PORT = 3000;
const SESSION_SECRET = 'your_session_secret'; // Replace with a secure key
const EMAIL_CONFIG = {
  service: 'gmail', // Or our email service
  auth: { user: 'your_email@gmail.com', pass: 'your_app_password' }, // Use app password for Gmail
};

// Middleware
app.use(bodyParser.json());
app.use(cookieSession({
  name: 'session',
  keys: [SESSION_SECRET],
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
}));

// Connect to MongoDB (replace with our connection string)
mongoose.connect(<connection string>, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Schemas and Models
const userSchema = new mongoose.Schema({
  username: String,
  email: { type: String, unique: true },
  password: String,
  resetToken: String,
  resetTokenExpiry: Date,
});
const User = mongoose.model('User', userSchema);

const categorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: String,
  type: { type: String, enum: ['expense', 'income'] },
});
const Category = mongoose.model('Category', categorySchema);

const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  amount: Number,
  description: String,
  date: Date,
  type: { type: String, enum: ['expense', 'income'] },
});
const Transaction = mongoose.model('Transaction', transactionSchema);

const budgetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  amount: { type: Number, min: 0 }, // Validation for positive amount
  period: { type: String, enum: ['monthly', 'yearly'] },
  startDate: Date,
});
const Budget = mongoose.model('Budget', budgetSchema);

// Middleware to check authentication via session
const authenticateSession = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// Authentication Endpoints
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    req.session.userId = user._id;
    res.status(201).json({ userId: user._id });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  req.session.userId = user._id;
  res.json({ message: 'Logged in' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session = null;
  res.json({ message: 'Logged out' });
});

// Password Recovery
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetToken = resetToken;
  user.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry
  await user.save();

  // Send email (configure nodemailer transport)
  const transporter = nodemailer.createTransport(EMAIL_CONFIG);
  const mailOptions = {
    from: 'your_email@gmail.com',
    to: email,
    subject: 'Password Reset',
    text: `Reset your password using this token: ${resetToken}`,
  };
  transporter.sendMail(mailOptions, (err) => {
    if (err) return res.status(500).json({ error: 'Email error' });
    res.json({ message: 'Reset email sent' });
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ error: 'Invalid or expired token' });

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;
  await user.save();
  res.json({ message: 'Password reset successful' });
});

// Categories Endpoints (Budget Categories CRUD with Validation)
app.post('/api/categories', authenticateSession, async (req, res) => {
  const { name, type } = req.body;
  if (!name || !type) return res.status(400).json({ error: 'Missing fields' });

  const category = new Category({ userId: req.session.userId, name, type });
  await category.save();
  res.status(201).json({ categoryId: category._id });
});

app.get('/api/categories', authenticateSession, async (req, res) => {
  const { type } = req.query;
  const filter = { userId: req.session.userId };
  if (type) filter.type = type;
  const categories = await Category.find(filter);
  res.json(categories);
});

app.put('/api/categories/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  const { name } = req.body;
  const category = await Category.findOneAndUpdate(
    { _id: id, userId: req.session.userId },
    { name },
    { new: true }
  );
  if (!category) return res.status(404).json({ error: 'Category not found' });
  res.json(category);
});

app.delete('/api/categories/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  // Check for linked transactions or budgets before delete
  const transactions = await Transaction.findOne({ categoryId: id });
  const budgets = await Budget.findOne({ categoryId: id });
  if (transactions || budgets) return res.status(400).json({ error: 'Category in use' });

  const category = await Category.findOneAndDelete({ _id: id, userId: req.session.userId });
  if (!category) return res.status(404).json({ error: 'Category not found' });
  res.status(204).send();
});

// Transactions Endpoints (CRUD with Filters)
app.post('/api/transactions', authenticateSession, async (req, res) => {
  const { amount, description, date, categoryId, type } = req.body;
  if (!amount || !date || !categoryId || !type) return res.status(400).json({ error: 'Missing fields' });
  if (amount <= 0) return res.status(400).json({ error: 'Amount must be positive' });

  const category = await Category.findOne({ _id: categoryId, userId: req.session.userId });
  if (!category) return res.status(404).json({ error: 'Category not found' });

  const transaction = new Transaction({
    userId: req.session.userId,
    categoryId,
    amount,
    description,
    date: new Date(date),
    type,
  });
  await transaction.save();
  res.status(201).json({ transactionId: transaction._id });
});

app.get('/api/transactions', authenticateSession, async (req, res) => {
  const { startDate, endDate, categoryId, type, page = 1, limit = 20 } = req.query;
  const filter = { userId: req.session.userId };
  if (startDate) filter.date = { ...filter.date, $gte: new Date(startDate) };
  if (endDate) filter.date = { ...filter.date, $lte: new Date(endDate) };
  if (categoryId) filter.categoryId = categoryId;
  if (type) filter.type = type;

  const transactions = await Transaction.find(filter)
    .sort({ date: -1 })
    .skip((page - 1) * limit)
    .limit(parseInt(limit));
  res.json(transactions);
});

app.put('/api/transactions/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  const updates = req.body; // Allow partial updates
  if (updates.amount && updates.amount <= 0) return res.status(400).json({ error: 'Amount must be positive' });

  const transaction = await Transaction.findOneAndUpdate(
    { _id: id, userId: req.session.userId },
    updates,
    { new: true }
  );
  if (!transaction) return res.status(404).json({ error: 'Transaction not found' });
  res.json(transaction);
});

app.delete('/api/transactions/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  const transaction = await Transaction.findOneAndDelete({ _id: id, userId: req.session.userId });
  if (!transaction) return res.status(404).json({ error: 'Transaction not found' });
  res.status(204).send();
});

// Budgets Endpoints (CRUD with Limit Validation)
app.post('/api/budgets', authenticateSession, async (req, res) => {
  const { categoryId, amount, period, startDate } = req.body;
  if (!categoryId || !amount || !period || !startDate) return res.status(400).json({ error: 'Missing fields' });
  if (amount <= 0) return res.status(400).json({ error: 'Budget amount must be positive' });

  const category = await Category.findOne({ _id: categoryId, userId: req.session.userId });
  if (!category) return res.status(404).json({ error: 'Category not found' });

  const budget = new Budget({
    userId: req.session.userId,
    categoryId,
    amount,
    period,
    startDate: new Date(startDate),
  });
  await budget.save();
  res.status(201).json({ budgetId: budget._id });
});

app.get('/api/budgets', authenticateSession, async (req, res) => {
  const budgets = await Budget.find({ userId: req.session.userId });
  // Optionally, calculate spent/remaining here for each
  res.json(budgets);
});

app.put('/api/budgets/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  if (updates.amount && updates.amount <= 0) return res.status(400).json({ error: 'Budget amount must be positive' });

  const budget = await Budget.findOneAndUpdate(
    { _id: id, userId: req.session.userId },
    updates,
    { new: true }
  );
  if (!budget) return res.status(404).json({ error: 'Budget not found' });
  res.json(budget);
});

app.delete('/api/budgets/:id', authenticateSession, async (req, res) => {
  const { id } = req.params;
  const budget = await Budget.findOneAndDelete({ _id: id, userId: req.session.userId });
  if (!budget) return res.status(404).json({ error: 'Budget not found' });
  res.status(204).send();
});

// Dashboard Overview Endpoint (Fetch Income, Expenses, Budgets with Aggregations)
app.get('/api/dashboard', authenticateSession, async (req, res) => {
  const { period = 'monthly', year = new Date().getFullYear(), month } = req.query;
  const userId = req.session.userId;

  // Date range for the period (simplified for monthly; extend for yearly)
  let startDate = new Date(year, month ? month - 1 : 0, 1);
  let endDate = new Date(year, month ? month : 12, 0);

  // Aggregate income and expenses
  const incomeAgg = await Transaction.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId), type: 'income', date: { $gte: startDate, $lte: endDate } } },
    { $group: { _id: null, totalIncome: { $sum: '$amount' } } },
  ]);
  const expensesAgg = await Transaction.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId), type: 'expense', date: { $gte: startDate, $lte: endDate } } },
    { $group: { _id: null, totalExpenses: { $sum: '$amount' } } },
  ]);

  const totalIncome = incomeAgg[0]?.totalIncome || 0;
  const totalExpenses = expensesAgg[0]?.totalExpenses || 0;
  const netSavings = totalIncome - totalExpenses;

  // Fetch budgets with spent calculations
  const budgets = await Budget.find({ userId });
  const budgetsWithSpent = await Promise.all(budgets.map(async (budget) => {
    const spentAgg = await Transaction.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId), categoryId: budget.categoryId, type: 'expense', date: { $gte: budget.startDate } } }, // Adjust date based on period
      { $group: { _id: null, spent: { $sum: '$amount' } } },
    ]);
    const spent = spentAgg[0]?.spent || 0;
    return { ...budget.toObject(), spent, remaining: budget.amount - spent };
  }));

  res.json({
    summary: { totalIncome, totalExpenses, netSavings },
    budgets: budgetsWithSpent,
  });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
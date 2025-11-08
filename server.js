const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'beekeeper',
  password: process.env.DB_PASSWORD || 'your_password',
  port: process.env.DB_PORT || 5432,
});

// Middleware
app.use(cors());
app.use(express.json());

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.userId = user.userId;
    next();
  });
};

// ========== AUTH ROUTES ==========

// Register
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    // Check if user exists
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists.' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user (email set to NULL)
    const result = await pool.query(
      'INSERT INTO users (username, password, email, created_at) VALUES ($1, $2, NULL, NOW()) RETURNING id, username',
      [username, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({ token, user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid username or password.' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid username or password.' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });

    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login.' });
  }
});

// Delete account
app.delete('/api/auth/account', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING username', [req.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    
    res.json({ message: 'Account deleted successfully.', username: result.rows[0].username });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({ error: 'Server error deleting account.' });
  }
});

// Update username
app.put('/api/auth/username', authenticateToken, async (req, res) => {
  const { username } = req.body;

  if (!username || username.length < 1) {
    return res.status(400).json({ error: 'Username must be at least 1 character.' });
  }

  try {
    // Check if username is already taken
    const existingUser = await pool.query('SELECT * FROM users WHERE username = $1 AND id != $2', [username, req.userId]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username already taken.' });
    }

    const result = await pool.query(
      'UPDATE users SET username = $1 WHERE id = $2 RETURNING id, username',
      [username, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Update username error:', error);
    res.status(500).json({ error: 'Server error updating username.' });
  }
});

// Update password
app.put('/api/auth/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password are required.' });
  }

  if (newPassword.length < 1) {
    return res.status(400).json({ error: 'Password must be at least 1 character.' });
  }

  try {
    // Get user's current password hash
    const result = await pool.query('SELECT password FROM users WHERE id = $1', [req.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = result.rows[0];

    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await pool.query(
      'UPDATE users SET password = $1 WHERE id = $2',
      [hashedPassword, req.userId]
    );

    res.json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ error: 'Server error updating password.' });
  }
});

// ========== HIVES ROUTES ==========

// Get all hives
app.get('/api/hives', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM hives WHERE user_id = $1 ORDER BY created_at DESC', [req.userId]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching hives:', error);
    res.status(500).json({ error: 'Server error fetching hives.' });
  }
});

// Create hive
app.post('/api/hives', authenticateToken, async (req, res) => {
  const { name, location, type, strength, queenAge, queenColor } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO hives (user_id, name, location, type, strength, queen_age, queen_color, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *',
      [req.userId, name, location, type, strength, queenAge, queenColor]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating hive:', error);
    res.status(500).json({ error: 'Server error creating hive.' });
  }
});

// Update hive
app.put('/api/hives/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, location, type, strength, queenAge, queenColor } = req.body;

  try {
    const result = await pool.query(
      'UPDATE hives SET name = $1, location = $2, type = $3, strength = $4, queen_age = $5, queen_color = $6 WHERE id = $7 AND user_id = $8 RETURNING *',
      [name, location, type, strength, queenAge, queenColor, id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Hive not found.' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating hive:', error);
    res.status(500).json({ error: 'Server error updating hive.' });
  }
});

// Delete hive
app.delete('/api/hives/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM hives WHERE id = $1 AND user_id = $2 RETURNING *', [id, req.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Hive not found.' });
    }
    
    res.json({ message: 'Hive deleted successfully.' });
  } catch (error) {
    console.error('Error deleting hive:', error);
    res.status(500).json({ error: 'Server error deleting hive.' });
  }
});

// ========== INSPECTIONS ROUTES ==========

// Get all inspections
app.get('/api/inspections', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT i.*, h.name as hive_name FROM inspections i JOIN hives h ON i.hive_id = h.id WHERE h.user_id = $1 ORDER BY i.date DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching inspections:', error);
    res.status(500).json({ error: 'Server error fetching inspections.' });
  }
});

// Create inspection
app.post('/api/inspections', authenticateToken, async (req, res) => {
  const { hiveId, date, broodPattern, temperament, varroaCount, honeyStores, notes } = req.body;

  try {
    // Verify hive belongs to user
    const hiveCheck = await pool.query('SELECT * FROM hives WHERE id = $1 AND user_id = $2', [hiveId, req.userId]);
    if (hiveCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Hive not found.' });
    }

    const result = await pool.query(
      'INSERT INTO inspections (hive_id, date, brood_pattern, temperament, varroa_count, honey_stores, notes, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *',
      [hiveId, date, broodPattern, temperament, varroaCount, honeyStores, notes]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating inspection:', error);
    res.status(500).json({ error: 'Server error creating inspection.' });
  }
});

// Delete inspection
app.delete('/api/inspections/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM inspections WHERE id = $1 AND hive_id IN (SELECT id FROM hives WHERE user_id = $2) RETURNING *',
      [id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Inspection not found.' });
    }
    
    res.json({ message: 'Inspection deleted successfully.' });
  } catch (error) {
    console.error('Error deleting inspection:', error);
    res.status(500).json({ error: 'Server error deleting inspection.' });
  }
});

// ========== TREATMENTS ROUTES ==========

// Get all treatments
app.get('/api/treatments', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT t.*, h.name as hive_name FROM treatments t JOIN hives h ON t.hive_id = h.id WHERE h.user_id = $1 ORDER BY t.start_date DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching treatments:', error);
    res.status(500).json({ error: 'Server error fetching treatments.' });
  }
});

// Create treatment
app.post('/api/treatments', authenticateToken, async (req, res) => {
  const { hiveId, type, startDate, endDate, withdrawalPeriod, notes } = req.body;

  try {
    const hiveCheck = await pool.query('SELECT * FROM hives WHERE id = $1 AND user_id = $2', [hiveId, req.userId]);
    if (hiveCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Hive not found.' });
    }

    const result = await pool.query(
      'INSERT INTO treatments (hive_id, type, start_date, end_date, withdrawal_period, notes, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *',
      [hiveId, type, startDate, endDate, withdrawalPeriod, notes]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating treatment:', error);
    res.status(500).json({ error: 'Server error creating treatment.' });
  }
});

// Delete treatment
app.delete('/api/treatments/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM treatments WHERE id = $1 AND hive_id IN (SELECT id FROM hives WHERE user_id = $2) RETURNING *',
      [id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Treatment not found.' });
    }
    
    res.json({ message: 'Treatment deleted successfully.' });
  } catch (error) {
    console.error('Error deleting treatment:', error);
    res.status(500).json({ error: 'Server error deleting treatment.' });
  }
});

// ========== HARVESTS ROUTES ==========

// Get all harvests
app.get('/api/harvests', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT h.*, hv.name as hive_name FROM harvests h JOIN hives hv ON h.hive_id = hv.id WHERE hv.user_id = $1 ORDER BY h.date DESC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching harvests:', error);
    res.status(500).json({ error: 'Server error fetching harvests.' });
  }
});

// Create harvest
app.post('/api/harvests', authenticateToken, async (req, res) => {
  const { hiveId, date, amount, notes } = req.body;

  try {
    const hiveCheck = await pool.query('SELECT * FROM hives WHERE id = $1 AND user_id = $2', [hiveId, req.userId]);
    if (hiveCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Hive not found.' });
    }

    const result = await pool.query(
      'INSERT INTO harvests (hive_id, date, amount, notes, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *',
      [hiveId, date, amount, notes]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating harvest:', error);
    res.status(500).json({ error: 'Server error creating harvest.' });
  }
});

// Delete harvest
app.delete('/api/harvests/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM harvests WHERE id = $1 AND hive_id IN (SELECT id FROM hives WHERE user_id = $2) RETURNING *',
      [id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Harvest not found.' });
    }
    
    res.json({ message: 'Harvest deleted successfully.' });
  } catch (error) {
    console.error('Error deleting harvest:', error);
    res.status(500).json({ error: 'Server error deleting harvest.' });
  }
});

// ========== TASKS ROUTES ==========

// Get all tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT t.*, h.name as hive_name FROM tasks t LEFT JOIN hives h ON t.hive_id = h.id WHERE t.user_id = $1 ORDER BY t.date ASC',
      [req.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).json({ error: 'Server error fetching tasks.' });
  }
});

// Create task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  const { name, hiveId, date, priority } = req.body;

  try {
    if (hiveId) {
      const hiveCheck = await pool.query('SELECT * FROM hives WHERE id = $1 AND user_id = $2', [hiveId, req.userId]);
      if (hiveCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Hive not found.' });
      }
    }

    const result = await pool.query(
      'INSERT INTO tasks (user_id, name, hive_id, date, priority, completed, created_at) VALUES ($1, $2, $3, $4, $5, false, NOW()) RETURNING *',
      [req.userId, name, hiveId || null, date, priority]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ error: 'Server error creating task.' });
  }
});

// Complete task
app.put('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found.' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error completing task:', error);
    res.status(500).json({ error: 'Server error completing task.' });
  }
});

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, req.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found.' });
    }
    
    res.json({ message: 'Task deleted successfully.' });
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).json({ error: 'Server error deleting task.' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Beekeeper API is running' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🐝 Beekeeper server running on port ${PORT}`);
});

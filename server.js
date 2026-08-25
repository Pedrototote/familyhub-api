const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Clave secreta para JWT
const SECRET_KEY = 'tu_clave_super_secreta_familyhub_2024';

// Pool de conexiones a MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ============ RUTAS DE PRUEBA ============

app.get('/', (req, res) => {
  res.json({ 
    message: '✅ FamilyHub API está funcionando',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// ============ AUTENTICACIÓN ============

// Signup - Crear cuenta
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, role, familyName } = req.body;
    
    if (!email || !password || !role) {
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const conn = await pool.getConnection();
    
    try {
      // Crear familia
      const [familyResult] = await conn.query(
        'INSERT INTO families (name) VALUES (?)',
        [familyName || 'Mi Familia']
      );
      const familyId = familyResult.insertId;
      
      // Crear usuario
      const [userResult] = await conn.query(
        'INSERT INTO users (email, password_hash, role, family_id) VALUES (?, ?, ?, ?)',
        [email, hashedPassword, role, familyId]
      );
      const userId = userResult.insertId;
      
      // Crear perfil de puntos
      await conn.query(
        'INSERT INTO user_points (family_id, user_role, total_points) VALUES (?, ?, ?)',
        [familyId, role, 0]
      );
      
      // JWT token
      const token = jwt.sign(
        { userId, email, role, familyId },
        SECRET_KEY,
        { expiresIn: '30d' }
      );
      
      res.json({ 
        success: true, 
        token, 
        userId, 
        familyId,
        message: 'Cuenta creada exitosamente'
      });
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Login - Iniciar sesión
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }
    
    const conn = await pool.getConnection();
    
    try {
      const [rows] = await conn.query(
        'SELECT id, password_hash, role, family_id FROM users WHERE email = ?',
        [email]
      );
      
      if (rows.length === 0) {
        return res.status(401).json({ error: 'Usuario no encontrado' });
      }
      
      const user = rows[0];
      const validPassword = await bcrypt.compare(password, user.password_hash);
      
      if (!validPassword) {
        return res.status(401).json({ error: 'Contraseña incorrecta' });
      }
      
      const token = jwt.sign(
        { userId: user.id, email, role: user.role, familyId: user.family_id },
        SECRET_KEY,
        { expiresIn: '30d' }
      );
      
      res.json({ 
        success: true, 
        token, 
        userId: user.id, 
        familyId: user.family_id,
        role: user.role
      });
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(400).json({ error: error.message });
  }
});

// ============ MIDDLEWARE DE AUTENTICACIÓN ============

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
};

// ============ TAREAS ============

// GET tareas de hoy
app.get('/api/tasks/today', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    const today = new Date().toISOString().split('T')[0];
    
    const conn = await pool.getConnection();
    try {
      const [tasks] = await conn.query(`
        SELECT t.*, 
               COALESCE(ts.status, 'pending') as status, 
               ts.started_at, 
               ts.completed_at
        FROM tasks t
        LEFT JOIN task_states ts ON t.id = ts.task_id AND ts.date = ?
        WHERE t.family_id = ?
        ORDER BY t.assigned_to, t.title
      `, [today, familyId]);
      
      res.json(tasks);
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(400).json({ error: error.message });
  }
});

// POST crear tarea
app.post('/api/tasks', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    const { title, assignedTo, recurrence, customDays, difficulty, estimatedTime, description } = req.body;
    
    if (!title || !assignedTo) {
      return res.status(400).json({ error: 'Título y usuario asignado requeridos' });
    }
    
    const conn = await pool.getConnection();
    try {
      const [result] = await conn.query(`
        INSERT INTO tasks (family_id, title, assigned_to, recurrence, custom_days, difficulty, estimated_time, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        familyId, 
        title, 
        assignedTo, 
        recurrence || 'once', 
        JSON.stringify(customDays || []), 
        difficulty || 'fácil', 
        estimatedTime || 10, 
        description || ''
      ]);
      
      res.json({ 
        success: true, 
        taskId: result.insertId,
        message: 'Tarea creada'
      });
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Create task error:', error);
    res.status(400).json({ error: error.message });
  }
});

// PUT cambiar estado de tarea
app.put('/api/tasks/:taskId/state', verifyToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;
    const today = new Date().toISOString().split('T')[0];
    
    if (!['pending', 'in_progress', 'completed'].includes(status)) {
      return res.status(400).json({ error: 'Estado inválido' });
    }
    
    const conn = await pool.getConnection();
    try {
      // Verificar que la tarea pertenece a la familia del usuario
      const [taskCheck] = await conn.query(
        'SELECT family_id FROM tasks WHERE id = ?',
        [taskId]
      );
      
      if (taskCheck.length === 0 || taskCheck[0].family_id !== req.user.familyId) {
        return res.status(403).json({ error: 'No tienes permiso' });
      }
      
      // Insertar o actualizar estado
      await conn.query(`
        INSERT INTO task_states (task_id, date, status, started_at, completed_at)
        VALUES (?, ?, ?, 
                IF(? = 'in_progress', NOW(), NULL),
                IF(? = 'completed', NOW(), NULL))
        ON DUPLICATE KEY UPDATE 
          status = ?,
          started_at = IF(? = 'in_progress', NOW(), started_at),
          completed_at = IF(? = 'completed', NOW(), completed_at)
      `, [taskId, today, status, status, status, status, status, status]);
      
      res.json({ success: true, message: 'Estado actualizado' });
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Update task state error:', error);
    res.status(400).json({ error: error.message });
  }
});

// DELETE eliminar tarea
app.delete('/api/tasks/:taskId', verifyToken, async (req, res) => {
  try {
    const { taskId } = req.params;
    
    const conn = await pool.getConnection();
    try {
      // Verificar permisos (solo admin o creador)
      const [taskCheck] = await conn.query(
        'SELECT family_id FROM tasks WHERE id = ?',
        [taskId]
      );
      
      if (taskCheck.length === 0 || taskCheck[0].family_id !== req.user.familyId) {
        return res.status(403).json({ error: 'No tienes permiso' });
      }
      
      await conn.query('DELETE FROM tasks WHERE id = ?', [taskId]);
      
      res.json({ success: true, message: 'Tarea eliminada' });
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(400).json({ error: error.message });
  }
});

// ============ EVENTOS ============

app.get('/api/events', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    
    const conn = await pool.getConnection();
    try {
      const [events] = await conn.query(`
        SELECT * FROM events 
        WHERE family_id = ? AND event_date >= CURDATE()
        ORDER BY event_date
      `, [familyId]);
      
      res.json(events);
    } finally {
      conn.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/events', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    const { title, eventDate, eventTime } = req.body;
    
    if (!title || !eventDate) {
      return res.status(400).json({ error: 'Título y fecha requeridos' });
    }
    
    const conn = await pool.getConnection();
    try {
      await conn.query(`
        INSERT INTO events (family_id, title, event_date, event_time, created_by)
        VALUES (?, ?, ?, ?, ?)
      `, [familyId, title, eventDate, eventTime || null, req.user.userId]);
      
      res.json({ success: true, message: 'Evento creado' });
    } finally {
      conn.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ GASTOS ============

app.get('/api/expenses', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    
    const conn = await pool.getConnection();
    try {
      const [expenses] = await conn.query(`
        SELECT * FROM expenses 
        WHERE family_id = ?
        ORDER BY expense_date DESC
      `, [familyId]);
      
      res.json(expenses);
    } finally {
      conn.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/expenses', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    const { description, amount, category, paidBy } = req.body;
    
    if (!description || !amount || !category) {
      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }
    
    const numAmount = parseFloat(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: 'Monto inválido' });
    }
    
    const conn = await pool.getConnection();
    try {
      const expenseDate = new Date().toISOString().split('T')[0];
      
      await conn.query(`
        INSERT INTO expenses (family_id, description, amount, category, paid_by, expense_date, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [familyId, description, numAmount, category, paidBy || null, expenseDate, req.user.userId]);
      
      res.json({ success: true, message: 'Gasto registrado' });
    } finally {
      conn.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ PUNTOS ============

app.get('/api/points', verifyToken, async (req, res) => {
  try {
    const { familyId } = req.user;
    
    const conn = await pool.getConnection();
    try {
      const [points] = await conn.query(`
        SELECT * FROM user_points 
        WHERE family_id = ?
        ORDER BY total_points DESC
      `, [familyId]);
      
      res.json(points);
    } finally {
      conn.release();
    }
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ============ SERVIDOR ============

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 FamilyHub API corriendo en puerto ${PORT}`);
  console.log(`📊 Base de datos: tuusuario_familyhub`);
  console.log(`✅ Listo para conectar desde FamilyHub.jsx`);
});
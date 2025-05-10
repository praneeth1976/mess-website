import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import path from "path";
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import qr from "qr-image";
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

// Number of salt rounds for bcrypt
const SALT_ROUNDS = 10;

app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files from root directory

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "itproject",
  password: "yourpassword",
  port: 5432,
});
db.connect();

// Ensure assets directory exists
const assetsDir = path.join(__dirname, 'assets');
if (!fs.existsSync(assetsDir)) {
  fs.mkdirSync(assetsDir);
}

// Root route redirect to login
app.get('/', (req, res) => {
  res.redirect('/index.html');
});

// Serve user page
app.get('/user.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'user.html'));
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve admin login page
app.get('/adminlogin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'adminlogin.html'));
});

// Serve admin page
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Serve admin dashboard
app.get('/admin-dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

// Generate and store QR code for user
function generateUserQR(userData) {
  // Create a URL for the user's profile page
  const profileUrl = `http://localhost:${port}/profile.html?id=${userData.id}`;
  
  const qrPath = path.join(assetsDir, `${userData.id}_qr.png`);
  const qr_svg = qr.image(profileUrl, { type: "png" });
  const qrStream = fs.createWriteStream(qrPath);
  
  return new Promise((resolve, reject) => {
    qr_svg.pipe(qrStream);
    qrStream.on("finish", () => {
      console.log(`QR code generated and stored for user ${userData.id} with URL: ${profileUrl}`);
      resolve();
    });
    qrStream.on("error", reject);
  });
}

// Serve user page with dynamic data
app.get('/user/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get user data from database
    const result = await db.query(
      "SELECT id, email FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }

    // Read the user.html file
    const userHtmlPath = path.join(__dirname, 'user.html');
    let userHtml = fs.readFileSync(userHtmlPath, 'utf8');

    // Fix the paths for CSS and assets
    userHtml = userHtml
      .replace(/href="\.\/style\.css"/g, 'href="/style.css"')
      .replace(/src="\.\/assets\//g, 'src="/assets/')
      .replace(/href="\.\/assets\//g, 'href="/assets/')
      .replace(/href="\.\//g, 'href="/')
      .replace(/src="\.\//g, 'src="/');

    // Replace both the QR code image source and its link href
    const qrCodePath = `/assets/${userId}_qr.png`;
    userHtml = userHtml.replace(
      /<a href="[^"]*"><img[^>]*><\/a>/,
      `<a href="${qrCodePath}"><img src="${qrCodePath}" alt="Your QR Code" style="max-width: 200px;"></a>`
    );

    // Add user data to the page
    userHtml = userHtml.replace(
      '</div>',
      `</div>
      <script>
        // Add user data to page
        const userData = {
          id: "${result.rows[0].id}",
          email: "${result.rows[0].email}"
        };
      </script>`
    );

    res.send(userHtml);
  } catch (error) {
    console.error("Error serving user page:", error);
    res.status(500).send('Internal server error');
  }
});

// Add user API endpoint
app.get('/api/user/:id', async (req, res) => {
  try {
    const userId = req.params.id;
    
    const result = await db.query(
      "SELECT id, email FROM users WHERE id = $1",
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// API endpoints
app.post("/api/register", async (req, res) => {
  try {
    const { rollNo, email, password } = req.body;
    
    // Check if user already exists
    const checkUser = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [rollNo]
    );

    if (checkUser.rows.length > 0) {
      return res.status(400).json({ error: "User already exists with this roll number" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new user with hashed password
    await db.query(
      "INSERT INTO users (id, email, password) VALUES ($1, $2, $3)",
      [rollNo, email, hashedPassword]
    );

    // Generate and store QR code without sending it in response
    await generateUserQR({ id: rollNo, email });

    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get user from database
    const result = await db.query(
      "SELECT * FROM users WHERE id = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare the provided password with the hashed password
    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.json({ 
        message: "Login successful",
        userId: user.id  // Send user ID in response
      });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create admin table if it doesn't exist
async function setupAdminTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id VARCHAR(50) PRIMARY KEY,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log("Admin table created successfully");
  } catch (error) {
    console.error("Error creating admin table:", error);
  }
}

// Add last_scan_time column to users table if it doesn't exist
async function setupUsersTable() {
  try {
    await db.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS last_scan_time TIMESTAMP WITH TIME ZONE
    `);
    console.log("Users table updated with last_scan_time column");
  } catch (error) {
    console.error("Error updating users table:", error);
  }
}

// Create feedback table if it doesn't exist
async function setupFeedbackTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS feedback (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        feedback_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Feedback table created successfully");
  } catch (error) {
    console.error("Error creating feedback table:", error);
  }
}

// Create complaint table if it doesn't exist
async function setupComplaintTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS complaints (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        complaint_text TEXT NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Complaint table created successfully");
  } catch (error) {
    console.error("Error creating complaint table:", error);
  }
}

// Create meal confirmations table if it doesn't exist
async function setupMealConfirmationsTable() {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS meal_confirmations (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(50) NOT NULL,
        will_attend BOOLEAN NOT NULL,
        meal_date DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    console.log("Meal confirmations table created successfully");
  } catch (error) {
    console.error("Error creating meal confirmations table:", error);
  }
}

// Initialize all tables
async function initializeTables() {
  await setupAdminTable();
  await setupUsersTable();
  await setupFeedbackTable();
  await setupComplaintTable();
  await setupMealConfirmationsTable();
}

// Call initializeTables when the server starts
initializeTables();

// Get user profile for QR scan
app.get("/api/admin/user-profile/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const adminId = req.headers['admin-id'];

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get user data
    const userResult = await db.query(
      "SELECT id, email, last_scan_time FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      user: userResult.rows[0]
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update scan time endpoint
app.post("/api/admin/update-scan", async (req, res) => {
  try {
    const { userId } = req.body;
    const adminId = req.headers['admin-id'];

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get current user data with last scan time
    const userResult = await db.query(
      "SELECT id, email, last_scan_time FROM users WHERE id = $1",
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = userResult.rows[0];
    const currentTime = new Date();
    
    // Check if last scan time exists and calculate time difference
    if (user.last_scan_time) {
      const lastScanTime = new Date(user.last_scan_time);
      const timeDiffInMinutes = (currentTime - lastScanTime) / (1000 * 60); // Convert to minutes
      
      // If less than 2 hours and 15 minutes (135 minutes) have passed
      if (timeDiffInMinutes < 135) {
        return res.status(400).json({ 
          error: "Cannot scan again",
          message: "User's meal is already completed. Please wait for the next meal time.",
          lastScanTime: user.last_scan_time,
          timeDiffInMinutes: Math.round(timeDiffInMinutes)
        });
      }
    }

    // Update last scan time
    const updateResult = await db.query(
      `UPDATE users 
       SET last_scan_time = CURRENT_TIMESTAMP 
       WHERE id = $1 
       RETURNING id, email, last_scan_time`,
      [userId]
    );

    res.json({
      message: "Scan time updated successfully",
      user: updateResult.rows[0]
    });
  } catch (error) {
    console.error("Error updating scan time:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin registration endpoint
app.post("/api/admin/register", async (req, res) => {
  try {
    const { username, email, password, secretKey } = req.body;

    // Verify secret key (you should change this to a secure value)
    const ADMIN_SECRET_KEY = "your-secure-admin-key";
    if (secretKey !== ADMIN_SECRET_KEY) {
      return res.status(403).json({ error: "Invalid secret key" });
    }
    
    // Check if admin already exists
    const checkAdmin = await db.query(
      "SELECT * FROM admins WHERE id = $1 OR email = $2",
      [username, email]
    );

    if (checkAdmin.rows.length > 0) {
      return res.status(400).json({ error: "Admin already exists with this username or email" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Insert new admin
    await db.query(
      "INSERT INTO admins (id, email, password) VALUES ($1, $2, $3)",
      [username, email, hashedPassword]
    );

    res.status(201).json({ message: "Admin registration successful" });
  } catch (error) {
    console.error("Admin registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin login endpoint
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get admin from database
    const result = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare the provided password with the hashed password
    const admin = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (passwordMatch) {
      res.json({ 
        message: "Admin login successful",
        adminId: admin.id
      });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin data endpoint (protected)
app.get("/api/admin/data", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all users data
    const usersResult = await db.query(
      "SELECT id, email, created_at FROM users ORDER BY created_at DESC"
    );

    res.json({
      users: usersResult.rows
    });
  } catch (error) {
    console.error("Error fetching admin data:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Feedback endpoint
app.post('/api/feedback', async (req, res) => {
  try {
    const { userId, feedback } = req.body;
    
    if (!userId || !feedback) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = 'INSERT INTO feedback (user_id, feedback_text) VALUES ($1, $2) RETURNING *';
    const values = [userId, feedback];
    
    const result = await db.query(query, values);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error submitting feedback:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Complaint endpoint
app.post('/api/complaint', async (req, res) => {
  try {
    const { userId, complaint } = req.body;
    
    if (!userId || !complaint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const query = 'INSERT INTO complaints (user_id, complaint_text) VALUES ($1, $2) RETURNING *';
    const values = [userId, complaint];
    
    const result = await db.query(query, values);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error submitting complaint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all feedback for admin
app.get("/api/admin/feedback", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all feedback with user details
    const feedbackResult = await db.query(`
      SELECT f.*, u.email as user_email 
      FROM feedback f 
      JOIN users u ON f.user_id = u.id 
      ORDER BY f.created_at DESC
    `);

    res.json({
      feedback: feedbackResult.rows
    });
  } catch (error) {
    console.error("Error fetching feedback:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all complaints for admin
app.get("/api/admin/complaints", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Get all complaints with user details
    const complaintsResult = await db.query(`
      SELECT c.*, u.email as user_email 
      FROM complaints c 
      JOIN users u ON c.user_id = u.id 
      ORDER BY c.created_at DESC
    `);

    res.json({
      complaints: complaintsResult.rows
    });
  } catch (error) {
    console.error("Error fetching complaints:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update complaint status
app.put("/api/admin/complaints/:id", async (req, res) => {
  try {
    const adminId = req.headers['admin-id'];
    const { id } = req.params;
    const { status } = req.body;

    if (!adminId) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Verify admin exists
    const adminResult = await db.query(
      "SELECT * FROM admins WHERE id = $1",
      [adminId]
    );

    if (adminResult.rows.length === 0) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Update complaint status
    const result = await db.query(
      "UPDATE complaints SET status = $1 WHERE id = $2 RETURNING *",
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Complaint not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error updating complaint:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete user API endpoint
app.delete('/api/admin/users/:userId', async (req, res) => {
    try {
        const adminId = req.headers['admin-id'];
        const userId = req.params.userId;

        // Verify admin authentication
        const adminResult = await db.query(
            "SELECT * FROM admins WHERE id = $1",
            [adminId]
        );

        if (adminResult.rows.length === 0) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        // Start a transaction
        await db.query('BEGIN');

        try {
            // Delete user's QR code file
            const qrPath = path.join(assetsDir, `${userId}_qr.png`);
            if (fs.existsSync(qrPath)) {
                fs.unlinkSync(qrPath);
            }

            // Delete user's feedback
            await db.query('DELETE FROM feedback WHERE user_id = $1', [userId]);

            // Delete user's complaints
            await db.query('DELETE FROM complaints WHERE user_id = $1', [userId]);

            // Delete user's meal confirmations if the table exists
            try {
                await db.query('DELETE FROM meal_confirmations WHERE user_id = $1', [userId]);
            } catch (error) {
                console.log('Meal confirmations table might not exist, skipping deletion');
            }

            // Finally, delete the user
            const result = await db.query('DELETE FROM users WHERE id = $1 RETURNING *', [userId]);

            if (result.rows.length === 0) {
                throw new Error('User not found');
            }

            // Commit the transaction
            await db.query('COMMIT');

            res.json({ message: 'User deleted successfully' });
        } catch (error) {
            // Rollback the transaction if anything fails
            await db.query('ROLLBACK');
            throw error;
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: error.message || 'Failed to delete user' });
    }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});


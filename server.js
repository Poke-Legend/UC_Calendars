// server.js - Main application file

// Import required modules
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const moment = require('moment');
const path = require('path');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer'); // For email-to-SMS

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Helper function to correctly format dates for display
function formatTimeForDisplay(dateTime) {
  if (!dateTime) return '';
  
  // Create proper date object to ensure local time interpretation
  const localDate = new Date(dateTime);
  return moment(localDate).format('h:mm A'); // 12-hour format with AM/PM
}

function formatDateTimeForDisplay(dateTime) {
  if (!dateTime) return '';
  
  // Create proper date object to ensure local time interpretation
  const localDate = new Date(dateTime);
  return moment(localDate).format('MMM D, YYYY h:mm A'); // e.g., "Apr 1, 2023 11:00 AM"
}

// Helper to format a date as YYYY-MM-DD for form inputs
function formatDateForInput(dateTime) {
  if (!dateTime) return '';
  
  const localDate = new Date(dateTime);
  return moment(localDate).format('YYYY-MM-DD');
}

// Helper to format a time as HH:MM for form inputs
function formatTimeForInput(dateTime) {
  if (!dateTime) return '';
  
  const localDate = new Date(dateTime);
  return moment(localDate).format('HH:mm');
}

// Improved date parsing function to ensure consistent handling
function parseDateTime(dateStr, timeStr) {
  if (!dateStr || !timeStr) return null;
  
  try {
    // Create ISO-8601 formatted datetime string
    const dateTimeStr = `${dateStr}T${timeStr}`;
    const result = new Date(dateTimeStr);
    
    // Check if the date is valid
    if (isNaN(result.getTime())) {
      return null;
    }
    
    return result;
  } catch (err) {
    return null;
  }
}

// Configure Gmail transporter for email-to-SMS
let gmailTransporter = null;

// Initialize the Gmail transporter
function initializeGmailTransporter() {
  if (gmailTransporter) return;
  
  // Check for Gmail credentials
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    return;
  }
  
  try {
    gmailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD // Use App Password, not your regular Gmail password
      }
    });
    
    // Verify transporter configuration
    gmailTransporter.verify(function(error, success) {
      if (error) {
        console.error('Gmail transporter verification failed:', error.message);
      }
    });
  } catch (err) {
    console.error('Failed to initialize Gmail transporter:', err.message);
  }
}

// Initialize Gmail transporter
initializeGmailTransporter();

// Map carrier names to their SMS gateway domains
const carrierGateways = {
  'verizon': 'vtext.com',
  'att': 'txt.att.net',
  'tmobile': 'tmomail.net',
  'sprint': 'messaging.sprintpcs.com',
  'boost': 'sms.myboostmobile.com',
  'cricket': 'sms.cricketwireless.net',
  'uscellular': 'email.uscc.net',
  'virgin': 'vmobl.com',
  'metro': 'mymetropcs.com',
  'xfinity': 'vtext.com',
  'straight': 'vtext.com',
  'consumer': 'mailmymobile.net',
  'google': 'msg.fi.google.com',
  'republic': 'text.republicwireless.com'
};

// Detect carrier based on phone number (simplified example)
function detectCarrier(phoneNumber) {
  // Default to a common carrier since we can't reliably detect
  return 'tmobile'; 
}

// Get the SMS gateway email for a phone number
function getSmsGatewayEmail(phoneNumber, carrier = null) {
  // Clean the phone number to remove any non-digit characters
  let cleanNumber = phoneNumber.replace(/\D/g, '');
  
  // Remove the + and country code (1) if present
  if (cleanNumber.startsWith('1')) {
    cleanNumber = cleanNumber.substring(1);
  }
  
  // Use provided carrier or detect it
  const carrierName = carrier || detectCarrier(phoneNumber);
  const gateway = carrierGateways[carrierName.toLowerCase()];
  
  if (!gateway) {
    return `${cleanNumber}@tmomail.net`;
  }
  
  return `${cleanNumber}@${gateway}`;
}

// Alternative carrier formats for when the standard format fails
function getAlternativeSmsGateway(phoneNumber, carrier) {
  // Clean the phone number to remove any non-digit characters
  let cleanNumber = phoneNumber.replace(/\D/g, '');
  
  // Remove the + and country code (1) if present
  if (cleanNumber.startsWith('1')) {
    cleanNumber = cleanNumber.substring(1);
  }
  
  // Alternative formats for common carriers (MMS gateways often work better)
  const alternativeFormats = {
    'verizon': `${cleanNumber}@vzwpix.com`, // MMS gateway
    'att': `${cleanNumber}@mms.att.net`,    // MMS gateway
    'tmobile': `${cleanNumber}@tmomail.net` // Same but included for completeness
  };
  
  const carrierName = carrier || 'tmobile';
  return alternativeFormats[carrierName.toLowerCase()] || null;
}

// Enhanced sendSmsViaEmail with fallback options
async function sendSmsViaEmail(phoneNumber, message, carrier = null) {
  // Make sure the Gmail transporter is initialized
  initializeGmailTransporter();
  
  if (!gmailTransporter) {
    return false;
  }
  
  const gatewayEmail = getSmsGatewayEmail(phoneNumber, carrier);
  
  // Limit message length to standard SMS length
  const smsText = message.substring(0, 160);
  
  try {
    const result = await gmailTransporter.sendMail({
      from: process.env.GMAIL_USER,
      to: gatewayEmail,
      subject: 'Union Circle Calendar', 
      text: smsText,
    });
    
    return true;
  } catch (err) {
    // Try alternative gateway format if standard fails
    const alternativeGateway = getAlternativeSmsGateway(phoneNumber, carrier);
    if (alternativeGateway) {
      try {
        const result2 = await gmailTransporter.sendMail({
          from: process.env.GMAIL_USER,
          to: alternativeGateway,
          subject: 'Union Circle Calendar', 
          text: smsText,
        });
        return true;
      } catch (err2) {
        return false;
      }
    }
    
    return false;
  }
}

// Create MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Initialize database tables
async function initDatabase() {
  try {
    const connection = await pool.getConnection();
    
    // Set session time zone to UTC for consistent handling
    await connection.query("SET time_zone = '+00:00'");
    
    // Create hosts table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS hosts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        rank VARCHAR(50) DEFAULT 'normal',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create host_ranks table if it doesn't exist
    try {
      await connection.query(`
        CREATE TABLE IF NOT EXISTS host_ranks (
          id INT AUTO_INCREMENT PRIMARY KEY,
          rank_name VARCHAR(50) NOT NULL UNIQUE,
          can_create_events BOOLEAN DEFAULT FALSE,
          description TEXT
        )
      `);
      
      // Check if ranks already exist
      const [existingRanks] = await connection.query('SELECT * FROM host_ranks');
      if (existingRanks.length === 0) {
        // Insert default ranks
        await connection.query(`
          INSERT INTO host_ranks (rank_name, can_create_events, description) VALUES
            ('normal', FALSE, 'Regular user, cannot host events'),
            ('ranked_hoster', TRUE, 'Approved host, can create and manage events'),
            ('admin', TRUE, 'Administrator with full privileges')
        `);
      }
    } catch (rankErr) {
      console.error('Error setting up host_ranks table:', rankErr.message);
    }
    
    // Create subscribers table with carrier field
    await connection.query(`
      CREATE TABLE IF NOT EXISTS subscribers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        phone_number VARCHAR(20) NOT NULL UNIQUE,
        carrier VARCHAR(50),
        subscription_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        active BOOLEAN DEFAULT TRUE
      )
    `);
    
    // Create events table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        description TEXT,
        start_time DATETIME NOT NULL,
        end_time DATETIME NOT NULL,
        game_world VARCHAR(100) DEFAULT 'Pokemon Legends',
        location VARCHAR(100),
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES hosts(id) ON DELETE CASCADE
      )
    `);
    
    // Create indexes for common query patterns
    try {
      await connection.query('CREATE INDEX IF NOT EXISTS idx_events_start_time ON events(start_time)');
      await connection.query('CREATE INDEX IF NOT EXISTS idx_events_created_by ON events(created_by)');
      await connection.query('CREATE INDEX IF NOT EXISTS idx_subscribers_active ON subscribers(active)');
      await connection.query('CREATE INDEX IF NOT EXISTS idx_subscribers_carrier ON subscribers(carrier)');
    } catch (indexErr) {
      // Ignore index errors - some MySQL versions don't support IF NOT EXISTS for indexes
    }
    
    connection.release();
  } catch (err) {
    console.error('Error initializing database:', err);
    process.exit(1);
  }
}

// Setup middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default_secret_change_in_production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Database helper functions

// Host methods
async function getHostById(id) {
  const [rows] = await pool.query('SELECT * FROM hosts WHERE id = ?', [id]);
  return rows[0];
}

async function getHostByUsername(username) {
  const [rows] = await pool.query('SELECT * FROM hosts WHERE username = ?', [username]);
  return rows[0];
}

async function createHost(username, password, email) {
  const [result] = await pool.query(
    'INSERT INTO hosts (username, password, email) VALUES (?, ?, ?)',
    [username, password, email]
  );
  return result.insertId;
}

// Host rank methods
async function getHostRank(hostId) {
  const [rows] = await pool.query('SELECT rank FROM hosts WHERE id = ?', [hostId]);
  if (rows.length === 0) {
    return null;
  }
  return rows[0].rank || 'normal';
}

async function canHostCreateEvents(hostId) {
  try {
    const [rows] = await pool.query(`
      SELECT hr.can_create_events 
      FROM hosts h
      JOIN host_ranks hr ON h.rank = hr.rank_name
      WHERE h.id = ?
    `, [hostId]);
    
    if (rows.length === 0) {
      return false;
    }
    return rows[0].can_create_events === 1;
  } catch (err) {
    return false;
  }
}

async function updateHostRank(hostId, newRank) {
  await pool.query('UPDATE hosts SET rank = ? WHERE id = ?', [newRank, hostId]);
}

// Event methods
async function getEvents(options = {}) {
  let query = 'SELECT e.*, h.username as host_username FROM events e LEFT JOIN hosts h ON e.created_by = h.id';
  const params = [];
  
  const conditions = [];
  
  if (options.upcomingOnly) {
    conditions.push('e.start_time >= NOW()');
  }
  
  if (options.hostId) {
    conditions.push('e.created_by = ?');
    params.push(options.hostId);
  }
  
  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  
  query += ' ORDER BY e.start_time ASC';
  
  const [rows] = await pool.query(query, params);
  
  // For MySQL, ensure the dates are proper JavaScript Date objects
  rows.forEach(event => {
    if (event.start_time && !(event.start_time instanceof Date)) {
      event.start_time = new Date(event.start_time);
    }
    
    if (event.end_time && !(event.end_time instanceof Date)) {
      event.end_time = new Date(event.end_time);
    }
  });
  
  return rows;
}

async function getEventById(id) {
  const [rows] = await pool.query(
    'SELECT * FROM events WHERE id = ?',
    [id]
  );
  
  if (rows.length === 0) return null;
  
  const event = rows[0];
  
  // Ensure dates are proper JavaScript Date objects
  if (event.start_time) {
    event.start_time = new Date(event.start_time);
  }
  
  if (event.end_time) {
    event.end_time = new Date(event.end_time);
  }
  
  return event;
}

async function createEvent(eventData) {
  const [result] = await pool.query(
    'INSERT INTO events (title, description, start_time, end_time, location, created_by) VALUES (?, ?, ?, ?, ?, ?)',
    [
      eventData.title,
      eventData.description,
      eventData.startTime,
      eventData.endTime,
      eventData.location,
      eventData.createdBy
    ]
  );
  return result.insertId;
}

async function updateEvent(id, eventData) {
  await pool.query(
    'UPDATE events SET title = ?, description = ?, start_time = ?, end_time = ?, location = ? WHERE id = ?',
    [
      eventData.title,
      eventData.description,
      eventData.startTime,
      eventData.endTime,
      eventData.location,
      id
    ]
  );
}

async function deleteEvent(id) {
  await pool.query('DELETE FROM events WHERE id = ?', [id]);
}

// Subscriber methods
async function getActiveSubscribers() {
  const [rows] = await pool.query('SELECT * FROM subscribers WHERE active = TRUE');
  return rows;
}

async function getSubscriberByPhoneNumber(phoneNumber) {
  const [rows] = await pool.query('SELECT * FROM subscribers WHERE phone_number = ?', [phoneNumber]);
  return rows[0];
}

async function createSubscriber(phoneNumber, carrier) {
  const [result] = await pool.query(
    'INSERT INTO subscribers (phone_number, carrier) VALUES (?, ?)',
    [phoneNumber, carrier]
  );
  return result.insertId;
}

async function updateSubscriber(id, data) {
  const setValues = [];
  const params = [];

  if (data.active !== undefined) {
    setValues.push('active = ?');
    params.push(data.active);
  }

  if (data.carrier) {
    setValues.push('carrier = ?');
    params.push(data.carrier);
  }

  if (setValues.length === 0) {
    return; // Nothing to update
  }

  params.push(id); // Add id for WHERE clause
  
  await pool.query(
    `UPDATE subscribers SET ${setValues.join(', ')} WHERE id = ?`,
    params
  );
}

// Function to add subscriber with carrier
async function addSubscriberWithCarrier(phoneNumber, carrier) {
  try {
    // First check if subscriber already exists
    const existingSubscriber = await getSubscriberByPhoneNumber(phoneNumber);
    
    if (existingSubscriber) {
      // Update existing subscriber with carrier info
      await updateSubscriber(existingSubscriber.id, { 
        carrier: carrier, 
        active: true 
      });
      
      return existingSubscriber.id;
    } else {
      // Create new subscriber with carrier info
      return await createSubscriber(phoneNumber, carrier);
    }
  } catch (err) {
    throw err;
  }
}

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.hostId) {
    return next();
  }
  res.redirect('/login');
};

// Middleware to check if host can create events
const canCreateEvents = async (req, res, next) => {
  try {
    const canCreate = await canHostCreateEvents(req.session.hostId);
    
    if (canCreate) {
      return next();
    }
    
    return res.render('rank-required', { 
      currentRank: await getHostRank(req.session.hostId) || 'normal'
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    const hostRank = await getHostRank(req.session.hostId);
    
    if (hostRank === 'admin') {
      return next();
    }
    
    return res.status(403).send('Admin privileges required');
  } catch (err) {
    res.status(500).send('Server error');
  }
};

// Function to schedule notifications for an event
async function scheduleEventNotifications(event) {
  try {
    const subscribers = await getActiveSubscribers();
    
    if (subscribers.length === 0) {
      return;
    }
    
    // Calculate time until event (for initial notification)
    const now = new Date();
    const eventTime = new Date(event.start_time);
    
    // If event is in the future, send initial notification
    if (eventTime > now) {
      // Format the event time with proper 12-hour format
      const formattedTime = moment(eventTime).format('MMMM Do YYYY, h:mm A'); // Note the 'h' for 12-hour format
      
      // Send to all active subscribers
      for (const subscriber of subscribers) {
        try {
          const message = `Union Circle: New event "${event.title}" on ${formattedTime} in Pokemon Legends.`;
          
          // Use the subscriber's carrier if available, otherwise detect it
          await sendSmsViaEmail(
            subscriber.phone_number, 
            message, 
            subscriber.carrier
          );
        } catch (err) {
          // Silently continue if a message fails
        }
      }
    }
    
    // Schedule one-hour-before reminder with correct time format
    const oneHourBefore = new Date(eventTime);
    oneHourBefore.setHours(oneHourBefore.getHours() - 1);
    
    if (oneHourBefore > now) {
      const timeUntilReminder = oneHourBefore.getTime() - now.getTime();
      
      setTimeout(async () => {
        const currentSubscribers = await getActiveSubscribers();
        
        // Format the exact event time with 12-hour format
        const exactTime = moment(eventTime).format('h:mm A'); // e.g., "11:00 AM"
        
        for (const subscriber of currentSubscribers) {
          try {
            const message = `REMINDER: Union Circle "${event.title}" starts in 1 hour at ${exactTime} in Pokemon Legends!`;
            
            await sendSmsViaEmail(
              subscriber.phone_number, 
              message, 
              subscriber.carrier
            );
          } catch (err) {
            // Silently continue if a message fails
          }
        }
      }, timeUntilReminder);
    }
  } catch (err) {
    // Log error but don't crash the application
    console.error('Failed to schedule notifications:', err.message);
  }
}

// Routes

// Home route - Public calendar view
// In the home route handler in server.js:
app.get('/', async (req, res) => {
  try {
    const events = await getEvents({ upcomingOnly: true });
    
    // Add formatted time to each event for display
    events.forEach(event => {
      // Make sure we're using the same date object in both places
      const startDate = new Date(event.start_time);
      const endDate = new Date(event.end_time);
      
      // Use the same formatting function for both displays
      event.formattedStartTime = formatTimeForDisplay(startDate);
      event.formattedEndTime = formatTimeForDisplay(endDate);
      event.formattedDate = moment(startDate).format('MMM D, YYYY');
      
      // Replace the original dates with the properly formatted ones
      event.start_time = startDate;
      event.end_time = endDate;
    });
    
    res.render('calendar', { 
      events,
      isAuthenticated: !!req.session.hostId,
      currentUser: req.session.username
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Login routes
app.get('/login', (req, res) => {
  if (req.session.hostId) {
    return res.redirect('/dashboard');
  }
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const host = await getHostByUsername(username);
    if (!host) {
      return res.render('login', { error: 'Invalid username or password' });
    }
    
    const isMatch = await bcrypt.compare(password, host.password);
    if (!isMatch) {
      return res.render('login', { error: 'Invalid username or password' });
    }
    
    req.session.hostId = host.id;
    req.session.username = host.username;
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Register routes (for new Union Circle Hosters)
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    
    // Check if username or email already exists
    const existingHost = await getHostByUsername(username);
    if (existingHost) {
      return res.render('register', { 
        error: 'Username already in use' 
      });
    }
    
    // Check if email already exists
    const [emailRows] = await pool.query('SELECT * FROM hosts WHERE email = ?', [email]);
    if (emailRows.length > 0) {
      return res.render('register', { 
        error: 'Email already in use' 
      });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new host
    await createHost(username, hashedPassword, email);
    res.redirect('/login');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Dashboard route (protected - only for authenticated hosts)
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const events = await getEvents({ hostId: req.session.hostId });
    
    // Add formatted time to each event for display
    events.forEach(event => {
      event.formattedStartTime = formatTimeForDisplay(event.start_time);
      event.formattedEndTime = formatTimeForDisplay(event.end_time);
      event.formattedDate = moment(event.start_time).format('MMM D, YYYY');
      event.formattedFullTime = formatDateTimeForDisplay(event.start_time);
    });
    
    // Get host info from database
    const [hostRows] = await pool.query('SELECT * FROM hosts WHERE id = ?', [req.session.hostId]);
    if (hostRows.length === 0) {
      return res.redirect('/logout');
    }
    
    const host = hostRows[0];
    
    // Default values if the host_ranks table isn't set up yet
    let canCreate = false;
    
    // Check if host can create events
    try {
      const [rankRows] = await pool.query(
        'SELECT can_create_events FROM host_ranks WHERE rank_name = ?', 
        [host.rank || 'normal']
      );
      
      if (rankRows.length > 0) {
        canCreate = rankRows[0].can_create_events === 1;
      }
    } catch (rankErr) {
      // If the host_ranks table doesn't exist yet, default to false
      canCreate = false;
    }
    
    res.render('dashboard', { 
      events,
      hostRank: host.rank || 'normal',
      canCreateEvents: canCreate
    });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Event routes
app.get('/events/new', isAuthenticated, canCreateEvents, (req, res) => {
  res.render('event-form');
});

app.post('/events', isAuthenticated, canCreateEvents, async (req, res) => {
  try {
    const { title, description, startDate, startTime, endDate, endTime, location } = req.body;
    
    // Parse date and time strings into Date objects with improved error handling
    const startDateTime = parseDateTime(startDate, startTime);
    const endDateTime = parseDateTime(endDate, endTime);
    
    if (!startDateTime || !endDateTime) {
      return res.status(400).send('Invalid date or time format. Please check your input.');
    }
    
    const eventId = await createEvent({
      title,
      description,
      startTime: startDateTime,
      endTime: endDateTime,
      location,
      createdBy: req.session.hostId
    });
    
    // Get the full event data to pass to notification function
    const newEvent = await getEventById(eventId);
    
    // Schedule SMS notifications
    await scheduleEventNotifications(newEvent);
    
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/events/:id/edit', isAuthenticated, async (req, res) => {
  try {
    const event = await getEventById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    if (event.created_by !== req.session.hostId) {
      return res.status(403).send('Unauthorized');
    }
    
    // Check if the host has permission to edit events
    const canCreate = await canHostCreateEvents(req.session.hostId);
    if (!canCreate) {
      return res.render('rank-required', { 
        currentRank: await getHostRank(req.session.hostId) || 'normal'
      });
    }
    
    // Add formatted date and time for form inputs
    event.formattedStartDate = formatDateForInput(event.start_time);
    event.formattedStartTime = formatTimeForInput(event.start_time);
    event.formattedEndDate = formatDateForInput(event.end_time);
    event.formattedEndTime = formatTimeForInput(event.end_time);
    
    res.render('event-edit', { event });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/events/:id', isAuthenticated, async (req, res) => {
  try {
    const { title, description, startDate, startTime, endDate, endTime, location } = req.body;
    
    const event = await getEventById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }
    
    if (event.created_by !== req.session.hostId) {
      return res.status(403).send('Unauthorized');
    }
    
    // Check if the host has permission to update events
    const canCreate = await canHostCreateEvents(req.session.hostId);
    if (!canCreate) {
      return res.render('rank-required', { 
        currentRank: await getHostRank(req.session.hostId) || 'normal'
      });
    }
    
    // Parse date and time strings into Date objects with improved error handling
    const startDateTime = parseDateTime(startDate, startTime);
    const endDateTime = parseDateTime(endDate, endTime);
    
    if (!startDateTime || !endDateTime) {
      return res.status(400).send('Invalid date or time format. Please check your input.');
    }
    
    await updateEvent(req.params.id, {
      title,
      description,
      startTime: startDateTime,
      endTime: endDateTime,
      location
    });
    
    // Get the updated event to pass to notification function
    const updatedEvent = await getEventById(req.params.id);
    
    // Re-schedule notifications
    await scheduleEventNotifications(updatedEvent);
    
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/events/:id/delete', isAuthenticated, async (req, res) => {
  try {
    const event = await getEventById(req.params.id);
    
    if (!event) {
      return res.status(404).send('Event not found');
    }

    if (event.created_by !== req.session.hostId) {
      return res.status(403).send('Unauthorized');
    }
    
    // Check if the host has permission to delete events
    const canCreate = await canHostCreateEvents(req.session.hostId);
    if (!canCreate) {
      return res.render('rank-required', { 
        currentRank: await getHostRank(req.session.hostId) || 'normal'
      });
    }
    
    await deleteEvent(req.params.id);
    
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Admin routes
app.get('/admin/hosts', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Get all hosts
    const [hosts] = await pool.query(`
      SELECT h.id, h.username, h.email, h.rank, h.created_at
      FROM hosts h
      ORDER BY h.username
    `);
    
    // Add event count and can_create_events for each host
    for (const host of hosts) {
      const [eventRows] = await pool.query(
        'SELECT COUNT(*) as count FROM events WHERE created_by = ?',
        [host.id]
      );
      host.event_count = eventRows[0].count;
      
      const [rankRows] = await pool.query(
        'SELECT can_create_events FROM host_ranks WHERE rank_name = ?',
        [host.rank || 'normal']
      );
      host.can_create_events = rankRows.length > 0 ? rankRows[0].can_create_events === 1 : false;
    }
    
    // Get all available ranks
    const [ranks] = await pool.query('SELECT * FROM host_ranks ORDER BY id');
    
    res.render('admin-hosts', { hosts, ranks });
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/admin/hosts/:id/rank', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { newRank } = req.body;
    const hostId = req.params.id;
    
    // Validate the new rank
    const [validRanks] = await pool.query('SELECT rank_name FROM host_ranks');
    const validRankNames = validRanks.map(r => r.rank_name);
    
    if (!validRankNames.includes(newRank)) {
      return res.status(400).send('Invalid rank');
    }
    
    // Update the host's rank
    await updateHostRank(hostId, newRank);
    
    res.redirect('/admin/hosts');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Subscriber routes
app.get('/subscribe', (req, res) => {
  res.render('subscribe');
});

app.post('/subscribe', async (req, res) => {
  try {
    const { phoneNumber, carrier } = req.body;
    
    // Format phone number to E.164 format
    const formattedPhoneNumber = phoneNumber.startsWith('+') 
      ? phoneNumber 
      : `+1${phoneNumber}`; // Assumes US number if no country code
    
    // Create or update subscriber with carrier info
    await addSubscriberWithCarrier(formattedPhoneNumber, carrier);
    
    // Send welcome message
    try {
      await sendSmsViaEmail(
        formattedPhoneNumber,
        'Welcome to Union Circle Calendar! You will now receive notifications for upcoming events.',
        carrier
      );
    } catch (smsErr) {
      // Continue even if the welcome message fails
    }
    
    res.render('subscribe-success');
  } catch (err) {
    res.render('subscribe', { error: 'Subscription failed: ' + err.message });
  }
});

app.get('/unsubscribe', (req, res) => {
  res.render('unsubscribe');
});

app.post('/unsubscribe', async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    
    // Format phone number
    const formattedPhoneNumber = phoneNumber.startsWith('+') 
      ? phoneNumber 
      : `+1${phoneNumber}`;
    
    const subscriber = await getSubscriberByPhoneNumber(formattedPhoneNumber);
    
    if (!subscriber) {
      return res.render('unsubscribe', { 
        error: 'This phone number is not subscribed' 
      });
    }
    
    await updateSubscriber(subscriber.id, { active: false });
    
    // Send confirmation message
    try {
      await sendSmsViaEmail(
        formattedPhoneNumber,
        'You have been unsubscribed from Union Circle Calendar notifications.',
        subscriber.carrier
      );
    } catch (smsErr) {
      // Continue even if the confirmation message fails
    }
    
    res.render('unsubscribe-success');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// API routes for potential frontend integration
app.get('/api/events', async (req, res) => {
  try {
    const events = await getEvents({ upcomingOnly: true });
    
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize database and start the server
initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Failed to initialize application:', err);
  });
    
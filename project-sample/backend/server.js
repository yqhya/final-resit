const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 555;
const SECRET_KEY = 'your-secret-key';

app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Authentication middleware (using cookies)
const authenticateToken = (req, res, next) => {
  const token = req.cookies.authToken || (req.headers['authorization'] && req.headers['authorization'].split(' ')[1]);
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin middleware
const isAdmin = (req, res, next) => {
  if (!req.user.isAdmin && req.user.isAdmin !== 1) {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Register
app.post('/user/register', (req, res) => {
  const { name, email, password, isAdmin } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (user) return res.status(400).json({ message: 'User already exists' });

    bcrypt.genSalt(10, (err, salt) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      bcrypt.hash(password, salt, (err, hashedPassword) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        const query = 'INSERT INTO users (name, email, password, isAdmin) VALUES (?, ?, ?, ?)';
        db.run(query, [name, email, hashedPassword, isAdmin ? 1 : 0], function(err) {
          if (err) return res.status(500).json({ message: 'Server error' });
          const newUser = {
            id: this.lastID,
            name,
            email,
            isAdmin: !!isAdmin
          };
          const token = jwt.sign(
            { id: newUser.id, email: newUser.email, isAdmin: newUser.isAdmin },
            SECRET_KEY,
            { expiresIn: '1h' }
          );
          res.cookie('authToken', token, {
            httpOnly: true,
            sameSite: 'none',
            secure: true,
            expires: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
          });
          res.status(201).json({
            message: 'User registered successfully',
            token,
            user: newUser
          });
        });
      });
    });
  });
});

// Login
app.post('/user/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM USER WHERE EMAIL = ?', [email], (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'Invalid credentials' });
    bcrypt.compare(password, user.PASSWORD, (err, isMatch) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
      const token = jwt.sign(
        { id: user.id, email: user.email, isAdmin: !!user.isAdmin },
        SECRET_KEY,
        { expiresIn: '1h' }
      );
      res.cookie('authToken', token, {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
        expires: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
      });
      res.json({
        message: 'Login successful',
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          isAdmin: !!user.isAdmin
        }
      });
    });
  });
});

// Logout
app.post('/user/logout', authenticateToken, (req, res) => {
  res.clearCookie('authToken');
  return res.status(200).send('Logged out successfully');
});

// Get all books
app.get('/books', (req, res) => {
  db.all('SELECT * FROM books', [], (err, books) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json(books);
  });
});

// Add book (admin only)
app.post('/books/add', authenticateToken, isAdmin, (req, res) => {
  const { title, author, description, price, quantity, imageUrl } = req.body;
  const query = 'INSERT INTO books (title, author, description, price, quantity, imageUrl) VALUES (?, ?, ?, ?, ?, ?)';
  db.run(query, [title, author, description, price, quantity, imageUrl], function(err) {
    if (err) return res.status(500).json({ message: 'Server error' });
    const newBook = {
      id: this.lastID,
      title,
      author,
      description,
      price,
      quantity,
      imageUrl
    };
    res.status(201).json(newBook);
  });
});

// Update book (admin only)
app.put('/books/:id', authenticateToken, isAdmin, (req, res) => {
  const { price, quantity } = req.body;
  const query = 'UPDATE books SET price = ?, quantity = ? WHERE id = ?';
  db.run(query, [price, quantity, req.params.id], function(err) {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.status(200).json({ message: 'Book updated successfully' });
  });
});

// Place order (any user)
app.post('/order', authenticateToken, (req, res) => {
  const { bookId, quantity } = req.body;
  db.get('SELECT * FROM books WHERE id = ?', [bookId], (err, book) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (!book) return res.status(404).json({ message: 'Book not found' });
    if (book.quantity < quantity) return res.status(400).json({ message: 'Not enough books in stock' });
    const newQuantity = book.quantity - quantity;
    db.run('UPDATE books SET quantity = ? WHERE id = ?', [newQuantity, bookId], (err) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      book.quantity = newQuantity;
      res.json({ message: 'Order placed successfully', book });
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

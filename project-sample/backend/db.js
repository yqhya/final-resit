const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Create a new database or open existing one
const dbPath = path.join(__dirname, 'bookstore.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        
        // Create users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            ISADMIN INT
        )`);

        // Create books table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            quantity INTEGER NOT NULL,
            imageUrl TEXT
        )`);

        // Insert initial books if the table is empty
        db.get('SELECT COUNT(*) as count FROM books', (err, row) => {
            if (err) {
                console.error('Error checking books:', err);
                return;
            }

            if (row.count === 0) {
                const initialBooks = [
                    {
                        title: "Harry Potter and the Philosopher's Stone",
                        author: "J.K. Rowling",
                        description: "Harry Potter's life is turned upside down on his eleventh birthday when a giant of a man, Hagrid, informs him that he is a wizard, and will attend Hogwarts School of Witchcraft and Wizardry.",
                        price: 19.99,
                        quantity: 10,
                        imageUrl: "https://m.media-amazon.com/images/I/5165He67NEL._SY291_BO1,204,203,200_QL40_FMwebp_.jpg"
                    },
                    {
                        title: "Harry Potter and the Chamber of Secrets",
                        author: "J.K. Rowling",
                        description: "Harry's second year at Hogwarts is filled with strange events as students are mysteriously petrified and a strange voice haunts him. Together with his friends, he must solve the mystery of the Chamber of Secrets.",
                        price: 21.99,
                        quantity: 8,
                        imageUrl: "https://m.media-amazon.com/images/I/51OZerWcGCL._SY291_BO1,204,203,200_QL40_FMwebp_.jpg"
                    },
                    {
                        title: "Harry Potter and the Prisoner of Azkaban",
                        author: "J.K. Rowling",
                        description: "Harry's third year at Hogwarts brings danger when an escaped prisoner from Azkaban, Sirius Black, is on the loose and believed to be hunting him. Harry learns more about his past and faces the terrifying Dementors.",
                        price: 23.99,
                        quantity: 12,
                        imageUrl: "https://m.media-amazon.com/images/I/51StPSSsneL._SY291_BO1,204,203,200_QL40_FMwebp_.jpg"
                    }
                ];

                const stmt = db.prepare('INSERT INTO books (title, author, description, price, quantity, imageUrl) VALUES (?, ?, ?, ?, ?, ?)');
                initialBooks.forEach(book => {
                    stmt.run([book.title, book.author, book.description, book.price, book.quantity, book.imageUrl]);
                });
                stmt.finalize();
            }
        });
    }
});

module.exports = db;

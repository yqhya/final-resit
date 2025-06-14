const express = require('express')
const cors = require('cors');
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const db_access = require('./Db.js')
const db = db_access.db
const cookieParser = require('cookie-parser');
const server = express()
const port = 555
const secret_key = 'DdsdsdKKFDDFDdvfddvxvcvc4dsdvdsvdb'

server.use(cors({
    origin:"http://localhost:3000",
    credentials:true
}))
server.use(express.json())
server.use(cookieParser())

const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, secret_key, { expiresIn: '1h' })
}

const verifyToken = (req, res, next) => {
    const token = req.cookies.authToken
    if (!token)
        return res.status(401).send('unauthorized')
    jwt.verify(token, secret_key, (err, details) => {
        if (err)
            return res.status(403).send('invalid or expired token')
        req.userDetails = details
        next()
    })
}

server.post('/user/login', (req, res) => {
    const email = req.body.email
    const password = req.body.password
    db.get(`SELECT * FROM USER WHERE EMAIL=?`, [email], (err, row) => {
        if (err || !row) {
            return res.status(401).send('invalid credentials')
        }
        bcrypt.compare(password, row.PASSWORD, (err, isMatch) => {
            if (err) {
                return res.status(500).send('error comparing password.')
            }
            if (!isMatch) {
                return res.status(401).send('invalid credentials')
            }
            else {
                let userID = row.ID
                let isAdmin = row.ISADMIN
                const token = generateToken(userID, isAdmin)

                res.cookie('authToken', token, {
                    httpOnly: true,
                    sameSite: 'none',
                    secure: true,
                    expiresIn: '1h'
                })
                return res.status(200).json({ id: userID, admin: isAdmin })
            }
        })
    })
})

server.post(`/user/register`, (req, res) => {
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            return res.status(500).send('error hashing password')
        }
        db.run(`INSERT INTO USER (name,email,password,isadmin) VALUES (?,?,?,?)`, [name, email, hashedPassword, 0], (err) => {
            if (err) {
                return res.status(401).send(err)
            }
            else
                return res.status(200).send(`registration successful`)
        })
    })
})

// Logout route
server.post('/user/logout', (req, res) => {
    res.clearCookie('authToken');
    return res.status(200).send('Logged out successfully');
});

// Book Management APIs
server.post(`/books/add`, verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin;
    if (isAdmin !== 1)
        return res.status(403).send("you are not an admin")
    
    const title = req.body.title
    const price = parseFloat(req.body.price)
    const quantity = parseInt(req.body.quantity, 10)
    
    let query = `INSERT INTO BOOK (TITLE, PRICE, QUANTITY) VALUES (?,?,?)`
    db.run(query, [title, price, quantity], (err) => {
        if (err) {
            console.log(err)
            return res.send(err)
        }
        else {
            return res.send(`book added successfully`)
        }
    })
})

server.get(`/books`, (req, res) => {
    const query = `SELECT * FROM BOOK WHERE QUANTITY > 0`
    db.all(query, (err, rows) => {
        if (err) {
            console.log(err)
            return res.send(err)
        }
        else {
            return res.json(rows)
        }
    })
})

server.get(`/books/:id`, (req, res) => {
    const query = `SELECT * FROM BOOK WHERE ID=?`
    db.get(query, [req.params.id], (err, row) => {
        if (err) {
            console.log(err)
            return res.send(err)
        }
        else if (!row)
            return res.send(`book with id ${req.params.id} not found`)
        else
            return res.send(row)
    })
})

server.put(`/books/update/:id`, verifyToken, (req, res) => {
    const isAdmin = req.userDetails.isAdmin;
    if (isAdmin !== 1)
        return res.status(403).send("you are not an admin")
    
    const quantity = parseInt(req.body.quantity, 10)
    const price = parseFloat(req.body.price)
    
    const query = `UPDATE BOOK SET QUANTITY=?, PRICE=? WHERE ID=?`
    db.run(query, [quantity, price, req.params.id], (err) => {
        if (err) {
            console.log(err)
            return res.send(err)
        }
        else {
            return res.send(`book updated successfully`)
        }
    })
})

server.post(`/order`, verifyToken, (req, res) => {
    const userID = req.userDetails.id
    const bookID = req.body.bookID
    const quantity = parseInt(req.body.quantity, 10)

    // First check if book exists and has enough quantity
    db.get(`SELECT * FROM BOOK WHERE ID=? AND QUANTITY >= ?`, [bookID, quantity], (err, book) => {
        if (err) {
            return res.status(500).send(err)
        }
        if (!book) {
            return res.status(400).send('Book not available in requested quantity')
        }

        // Create order and update book quantity
        db.run('BEGIN TRANSACTION', (err) => {
            if (err) {
                return res.status(500).send(err)
            }

            db.run(`INSERT INTO ORDERS (USER_ID, BOOK_ID, QUANTITY) VALUES (?, ?, ?)`,
                [userID, bookID, quantity], (err) => {
                    if (err) {
                        db.run('ROLLBACK')
                        return res.status(500).send(err)
                    }

                    db.run(`UPDATE BOOK SET QUANTITY = QUANTITY - ? WHERE ID = ?`,
                        [quantity, bookID], (err) => {
                            if (err) {
                                db.run('ROLLBACK')
                                return res.status(500).send(err)
                            }

                            db.run('COMMIT', (err) => {
                                if (err) {
                                    db.run('ROLLBACK')
                                    return res.status(500).send(err)
                                }
                                return res.status(200).send('Order placed successfully')
                            })
                        })
                })
        })
    })
})

server.get(`/orders`, verifyToken, (req, res) => {
    const userID = req.userDetails.id
    const isAdmin = req.userDetails.isAdmin

    let query = `
        SELECT O.ID as ORDER_ID, B.TITLE, O.QUANTITY, B.PRICE, U.NAME as USER_NAME
        FROM ORDERS O
        JOIN BOOK B ON O.BOOK_ID = B.ID
        JOIN USER U ON O.USER_ID = U.ID
    `
    
    if (!isAdmin) {
        query += ` WHERE O.USER_ID = ?`
        db.all(query, [userID], (err, rows) => {
            if (err) {
                return res.status(500).send(err)
            }
            return res.json(rows)
        })
    } else {
        db.all(query, (err, rows) => {
            if (err) {
                return res.status(500).send(err)
            }
            return res.json(rows)
        })
    }
})

// Initialize database tables
db.serialize(() => {
    db.run(db_access.createUserTable)
    db.run(db_access.createBookTable)
    db.run(db_access.createOrderTable)
    
    // Add initial Harry Potter books if they don't exist
    db.get(`SELECT COUNT(*) as count FROM BOOK`, (err, row) => {
        if (err) {
            console.error('Error checking books:', err)
            return
        }
        if (row.count === 0) {
            const initialBooks = [
                ['Harry Potter and the Philosopher\'s Stone', 19.99, 10],
                ['Harry Potter and the Chamber of Secrets', 19.99, 10],
                ['Harry Potter and the Prisoner of Azkaban', 19.99, 10]
            ]
            
            initialBooks.forEach(book => {
                db.run(`INSERT INTO BOOK (TITLE, PRICE, QUANTITY) VALUES (?, ?, ?)`, book)
            })
        }
    })
})

server.listen(port, () => {
    console.log(`Server is running on port ${port}`)
})

const express = require('express');
require('dotenv').config();
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const Joi = require('joi');
const xss = require('xss'); 
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const connection = require('./config/db');
const multer = require('multer');
const path = require('path');
const session = require('express-session');
const snap = require('./config/midtrans');


const app = express();

const KEY = process.env.ENCRYPTION_KEY;
const IV = process.env.IV;
const SECRECT_KEY = 'SecretAdminBrowser';
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors({ origin: 'http://localhost:5500', credentials: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(session({
    secret: SECRECT_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false,               
        httpOnly: true,
        sameSite: 'lax',               
        maxAge: 24 * 60 * 60 * 1000    
    }
}));


const csrfProtection = csrf({ cookie: true });

var tokens = []
app.get('/csrf-token', csrfProtection, (req, res) => {
    const csrfToken = req.csrfToken(); 
    tokens.push(csrfToken);
    console.log('Token yang dihasilkan:', csrfToken); 
    res.json({ csrfToken }); 
  });

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `${uniqueSuffix}-${file.originalname}`);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedExtensions = /jpeg|jpg|png|gif/;
    const extName = allowedExtensions.test(path.extname(file.originalname).toLowerCase());
    const mimeType = allowedExtensions.test(file.mimetype);
    if (extName && mimeType) {
        cb(null, true);
    } else {
        cb(new Error('Only images are allowed!'));
    }
};

const upload = multer({ 
    storage,
    fileFilter,
    limits: { fileSize: 2 * 1024 * 1024 } 
});

// REGISTRATION ROUTE 

// Joi validation schema for registration
const registerValidator = Joi.object({
    _csrf: Joi.string(),
    name: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).max(30).required(),
    phone: Joi.string().pattern(/^[0-9]+$/).required(),
    website: Joi.string().uri().required(),
    birthplace: Joi.string().required(),
    birthdate: Joi.date().required(),
    nokk: Joi.string().pattern(/^[0-9]+$/).required(),
    no_ktp: Joi.string().pattern(/^[0-9]+$/).required(),
});

function encryptData(plaintext) {
    let ciper = crypto.createCipheriv('aes-256-cbc', KEY, IV );
    let encrpt = ciper.update(plaintext, 'utf8', 'hex');
    
    encrpt += ciper.final('hex');

    return encrpt
}

function decryptData(encryptedText) {
    let decipher = crypto.createDecipheriv('aes-256-cbc', KEY, IV);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// POST route for registration
app.post('/signup', upload.single('photo'), async (req, res) => {
    const { error, value } = registerValidator.validate(req.body);
    if (error) {
        return res.send(`
            <script>
              alert(\`Error: ${error.details[0].message}\`);
              window.history.back();
            </script>
        `);
    }

    const clientToken = req.body._csrf;
    const tokenIndex = tokens.indexOf(clientToken);

    if (tokenIndex === -1) {
        // Jika token tidak ditemukan, kirimkan error
        console.log('Token tidak ditemukan:', clientToken);
        return res.status(403).send('CSRF token mismatch');
    }

    // Jika token valid, hapus token dari array dan proses request
    tokens.splice(tokenIndex, 1); // Hapus token dari array

    try {
        const sanitizedPassword = xss(value.password);
        const hashedPassword = await bcrypt.hash(sanitizedPassword, 10);

        // Sanitasi dan enkripsi data lainnya
        const sanitizedName = encryptData(xss(value.name));
        const sanitizedEmail = encryptData(xss(value.email));
        const sanitizedPhone = encryptData(xss(value.phone));
        const sanitizedWebsite = encryptData(xss(value.website));
        const sanitizedBirthplace = encryptData(xss(value.birthplace));
        const sanitizedBirthdate = encryptData(xss(value.birthdate));
        const sanitizedNokk = encryptData(xss(value.nokk));
        const sanitizedNoKtp = encryptData(xss(value.no_ktp));

        // Proses foto
        const photoPath = req.file.path; // Path asli di folder
        const encryptedPhotoName = encryptData(req.file.filename); // Nama file terenkripsi

        // Simpan ke database
        const query = `
            INSERT INTO users (
                email, password, nama, nomor_hp, alamat_web, tempat_lahir, 
                tanggal_lahir, no_kk, no_ktp, photo
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

        connection.query(query, [
            sanitizedEmail,
            hashedPassword,
            sanitizedName,
            sanitizedPhone,
            sanitizedWebsite,
            sanitizedBirthplace,
            sanitizedBirthdate,
            sanitizedNokk,
            sanitizedNoKtp,
            encryptedPhotoName // Nama terenkripsi ke database
        ], (err, result) => {
            if (err) throw err;
            console.log('User registered:', result.insertId);
            res.redirect('http://localhost:5500/');
        });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).send('Internal server error');
    }
});

app.use((err, req, res, next) => {
    if (err.code !== "EBADCSRFTOKEN") return next(err);
    res.status(403).json({ error: "CSRF token validation failed" });
  });


// ----------------------------
// LOGIN ROUTE WITH Joi VALIDATION
// ----------------------------

// Joi validation schema for login
const loginValidator = Joi.object({
    _csrf : Joi.string(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

// POST route for login
app.post('/signin', async (req, res) => {
    const { error, value } = loginValidator.validate(req.body);

    if (error) {
        return res.send(`
            <script>
              alert(\`Error: ${error.details[0].message}\`);
              window.history.back();
            </script>
        `);
    }
    const clientToken = req.body._csrf;
    const tokenIndex = tokens.indexOf(clientToken);

    if (tokenIndex === -1) {
        // Jika token tidak ditemukan, kirimkan error
        console.log('Token tidak ditemukan:', clientToken);
        return res.status(403).send('CSRF token mismatch');
    }

    // Jika token valid, hapus token dari array dan proses request
    tokens.splice(tokenIndex, 1); // Hapus token dari array

    try {
        // Sanitasi input
        const sanitizedEmail = xss(value.email);
        const sanitizedPassword = xss(value.password);

        // Enkripsi email input pengguna untuk mencocokkan dengan database
        const encryptedEmail = encryptData(sanitizedEmail);
        console.log(encryptedEmail)
        // Query untuk mencocokkan email dan password
        const query = `SELECT * FROM users WHERE email = ?`;

        connection.query(query, [encryptedEmail], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Internal server error');
            }

            if (results.length === 0) {
                return res.send(`
                    <script>
                      alert("Invalid Email or Password");
                      window.history.back();
                    </script>
                `);
            }

            const user = results[0];

            // Validasi password (bcrypt.compare)
            const passwordMatch = await bcrypt.compare(sanitizedPassword, user.password);

            if (!passwordMatch) {
                return res.send(`
                    <script>
                      alert("Invalid Email or Password");
                      window.history.back();
                    </script>
                `);
            }

            req.session.user_id = user.id;
            req.session.user_name = decryptData(user.nama);

            // Redirect ke halaman member
            res.redirect("http://localhost:5500/member.html");
        });
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Internal server error');
    }
});

app.get('/api/get-user-id', (req, res) => {
    if (!req.session.user_id) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json({ 
        user_id: req.session.user_id,
        name: req.session.user_name
    });
});
app.get('/api/profile', (req, res) => {
    if (!req.session.user_id) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const query = 'SELECT email, nama, nomor_hp, alamat_web, tempat_lahir, tanggal_lahir, no_kk, no_ktp, photo FROM users WHERE id = ?';
    connection.query(query, [req.session.user_id], (err, results) => {
        console.log(results)
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = results[0];

        const decryptedUser = {
            email: decryptData(user.email),
            nama: decryptData(user.nama),
            nomor_hp: decryptData(user.nomor_hp),
            alamat_web: decryptData(user.alamat_web),
            tempat_lahir: decryptData(user.tempat_lahir),
            tanggal_lahir: decryptData(user.tanggal_lahir),
            no_kk: decryptData(user.no_kk),
            no_ktp: decryptData(user.no_ktp),
            photo: user.photo ? `http://localhost:3000/uploads/${decryptData(user.photo)}` : null
        };
        console.log(decryptedUser);

        res.json(decryptedUser);
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Internal server error');
        }
        res.clearCookie('connect.sid'); // Hapus cookie session
        res.json({ message: 'Logged out successfully' });
    });
});

const schemaProdcuts = Joi.object({
    _csrf: Joi.string(),
    nama: Joi.string().min(3).max(255).required(),
    deskripsi: Joi.string().min(10).max(1000).required(),
    harga: Joi.number().greater(0).required(),
    user_id: Joi.number().integer().required(),
    photo: Joi.string().optional() // foto optional
});


app.post('/add-product', upload.single('photo'), (req, res) => {
    console.log(req.session.user_id)
    try {
        
        const clientToken = req.body._csrf;
        const tokenIndex = tokens.indexOf(clientToken);

        // Validate CSRF token
        if (tokenIndex === -1) {
            console.log('Token not found:', clientToken);
            return res.status(403).send('CSRF token mismatch');
        }

        // Remove token after use
        tokens.splice(tokenIndex, 1);

        // Validate input using Joi
        const schema = Joi.object({
            nama: Joi.string().max(255).required(),
            deskripsi: Joi.string().allow(''),
            harga: Joi.number().positive().required(),
        });

        const { error, value } = schema.validate({
            nama: xss(req.body.nama),
            deskripsi: xss(req.body.deskripsi),
            harga: req.body.harga,
        });

        if (error) {
            console.error('Validation error:', error.details[0].message);
            return res.status(400).json({ message: error.details[0].message });
        }

        const { nama, deskripsi, harga } = value;

        // Encrypt data
        const encryptedNama = encryptData(nama);
        const encryptedDeskripsi = encryptData(deskripsi);
        const encryptedHarga = encryptData(harga.toString());
        const encryptedPhoto = req.file ? encryptData(req.file.filename) : null;

        // Insert data into database
        const query = `
            INSERT INTO products (nama, deskripsi, harga, user_id, photo)
            VALUES (?, ?, ?, ?, ?)
        `;
        const values = [
            encryptedNama,
            encryptedDeskripsi,
            encryptedHarga,
            req.session.user_id,
            encryptedPhoto,
        ];

        connection.query(query, values, (err, result) => {
            if (err) {
                console.error('Database error:', err.message);
                return res.status(500).json({ message: 'Database error' });
            }

            res.status(200).json({ message: 'Product added successfully' });
        });
    } catch (err) {
        console.error('Error adding product:', err);
        res.status(500).send('Internal server error');
    }
});



app.delete('/delete-product/:id', async (req, res) => {
    const productId = parseInt(req.params.id, 10);
    const query = 'DELETE FROM products WHERE id = ?';
    connection.query(query, [productId], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Internal server error');
        }
        res.json({ message: 'Product deleted successfully' });
    });
});

app.get('/get-product/:id', (req, res) => {
    const productId = parseInt(req.params.id, 10);

    const query = 'SELECT * FROM products WHERE id = ?';
    connection.query(query, [productId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Internal server error');
        }
        if (results.length === 0) {
            return res.status(404).send('Product not found');
        }

        const product = results[0];
        const decryptedProduct = {
            id: product.id,
            nama: decryptData(product.nama),
            deskripsi: decryptData(product.deskripsi),
            harga: decryptData(product.harga),
            photo: product.photo ? `http://localhost:3000/uploads/${decryptData(product.photo)}` : null,
        };

        console.log('Decrypted product:', decryptedProduct);

        res.json(decryptedProduct);
    });
});

app.post('/edit-product/:id', upload.single('photo'), (req, res) => {
    const clientToken = req.body._csrf;
    const tokenIndex = tokens.indexOf(clientToken);

    // Validasi token CSRF
    if (tokenIndex === -1) {
        console.log('Token tidak ditemukan:', clientToken);
        return res.status(403).send('CSRF token mismatch');
    }

    // Hapus token setelah digunakan
    tokens.splice(tokenIndex, 1);

    // Validasi input menggunakan Joi
    const schema = Joi.object({
        nama: Joi.string().max(255).required(),
        deskripsi: Joi.string().allow(''),
        harga: Joi.number().positive().required(),
    });

    const { error, value } = schema.validate({
        nama: xss(req.body.nama),
        deskripsi: xss(req.body.deskripsi),
        harga: req.body.harga,
    });

    if (error) {
        console.error('Validation error:', error.details[0].message);
        return res.status(400).json({ message: error.details[0].message });
    }

    const { nama, deskripsi, harga } = value;

    // Enkripsi data
    const encryptedNama = encryptData(nama);
    const encryptedDeskripsi = encryptData(deskripsi);
    const encryptedHarga = encryptData(harga.toString());
    const encryptedPhoto = req.file ? encryptData(req.file.filename) : null;

    // Update database
    const query = `
        UPDATE products
        SET nama = ?, deskripsi = ?, harga = ?, photo = IFNULL(?, photo)
        WHERE id = ? AND user_id = ?;
    `;
    const values = [
        encryptedNama,
        encryptedDeskripsi,
        encryptedHarga,
        encryptedPhoto, 
        req.params.id,
        req.session.user_id,
    ];

    connection.execute(query, values, (err, result) => {
        if (err) {
            console.error('Database error:', err.message);
            return res.status(500).json({ message: 'Database error' });
        }

        res.status(200).json({ message: 'Product updated successfully' });
    });
});

app.get('/list-products-self', async (req, res) => {
    try {
        if (!req.session.user_id) {
            console.error('Session user_id is missing');
            return res.status(401).json({ error: 'Unauthorized' });
        }

        console.log('Session user_id:', req.session.user_id);

        const userId = req.session.user_id;

        const query = 'SELECT * FROM products WHERE user_id = ?';
        connection.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Internal server error');
            }

            const products = results.map(product => ({
                id: product.id,
                nama: decryptData(product.nama),
                deskripsi: decryptData(product.deskripsi),
                harga: decryptData(product.harga),
                photo: product.photo ? `http://localhost:3000/uploads/${decryptData(product.photo)}` : null,
                user_id: product.user_id,
            }));

            res.json(products);
        });
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).send('Internal server error');
    }
});

app.get('/list-products', async (req, res) => {
    try {
        if (!req.session.user_id) {
            console.error('Session user_id is missing');
            return res.status(401).json({ error: 'Unauthorized' });
        }

        console.log('Session user_id:', req.session.user_id);

        const userId = req.session.user_id;

        const query = 'SELECT * FROM products WHERE user_id != ?';
        connection.query(query, [userId], (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).send('Internal server error');
            }

            const products = results.map(product => ({
                id: product.id,
                nama: decryptData(product.nama),
                deskripsi: decryptData(product.deskripsi),
                harga: decryptData(product.harga),
                photo: product.photo ? `http://localhost:3000/uploads/${decryptData(product.photo)}` : null,
                user_id: product.user_id,
            }));

            res.json(products);
        });
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).send('Internal server error');
    }
});

app.post('/api/create-transaction', async (req, res) => {
    try {
        const { product_id } = req.body;

        if (!product_id) {
            return res.status(400).json({ error: 'Product ID is required' });
        }

        // Query database untuk mengambil detail produk
        const productQuery = 'SELECT id, nama, harga FROM products WHERE id = ?';
        connection.query(productQuery, [product_id], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Internal server error' });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }

            const productDetails = results[0];
            console.log(productDetails);
            const user_id = req.session.user_id;

            // Query untuk mengambil data pengguna
            const userQuery = 'SELECT * FROM users WHERE ID = ?';
            connection.query(userQuery, [user_id], async (err, hasil) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ error: 'Internal server error' });
                }

                if (hasil.length === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }
            const user = hasil[0];
            console.log(user)

                const productPrice = decryptData(productDetails.harga);
                const productName = decryptData(productDetails.nama);
                const orderId = `ORDER-${Date.now()}-${productDetails.id}`;
                const encryptedOrderId = encryptData(orderId);
                const parameter = {
                    transaction_details: {
                        order_id: orderId, 
                        gross_amount: parseFloat(productPrice),
                    },
                    item_details: [
                        {
                            id: productDetails.id,
                            price: parseFloat(productPrice),
                            quantity: 1,
                            name: productName,
                        },
                    ],
                    customer_details: {
                        "first_name": decryptData(user.nama),
                        "email" : decryptData(user.email),
                        "phone" : decryptData(user.nomor_hp)
                    }, 
                    credit_card: {
                        secure: true,
                    },
                };

                // Buat transaksi
                const transaction = await snap.createTransaction(parameter);
                const encryptedTransUrl = encryptData(transaction.redirect_url);
                const encryptedStatus = encryptData('pending');

                // Simpan transaksi ke database dengan status pending
                const insertQuery = `
                    INSERT INTO transactions (user_id, product_id, order_id, status, payment_link)
                    VALUES (?, ?, ?, ?, ?)
                `;
                connection.query(insertQuery, [user_id, product_id, encryptedOrderId, encryptedStatus, encryptedTransUrl], (err) => {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ error: 'Failed to save transaction' });
                    }

                    // Kirim token dan payment link ke frontend
                    res.json({
                        message: 'Transaction token created successfully',
                        token: transaction.token,
                        payment_link: transaction.redirect_url,
                    });
                });
            });
        });
    } catch (err) {
        console.error('Error creating transaction:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.post('/api/update-transaction', (req, res) => {
    const { order_id, status } = req.body;

    if (!order_id || !status) {
        return res.status(400).json({ error: 'Order ID and status are required' });
    }

    // Enkripsi order_id dan status sebelum disimpan
    const encryptedOrderId = encryptData(order_id);
    const encryptedStatus = encryptData(status);

    const query = `
        UPDATE transactions
        SET status = ?, order_id = ?
        WHERE order_id = ?
    `;

    connection.query(query, [encryptedStatus, encryptedOrderId, encryptedOrderId], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update transaction' });
        }

        res.json({ message: 'Transaction updated successfully' });
    });
});


app.get('/api/transactions', (req, res) => {
    const userId = req.session.user_id; 

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized: User not logged in' });
    }

    const query = `
        SELECT 
            t.order_id, 
            t.status, 
            t.payment_link, 
            u.nama AS user_name, 
            p.nama AS product_name 
        FROM transactions t
        INNER JOIN users u ON t.user_id = u.id
        INNER JOIN products p ON t.product_id = p.id
        WHERE t.user_id = ?
        ORDER BY t.order_id DESC
    `;

    connection.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        console.log(results)
        const decryptedResults = results.map(transaction => ({
            order_id: decryptData(transaction.order_id),
            status: decryptData(transaction.status),
            payment_link: decryptData(transaction.payment_link),
            user_name: decryptData(transaction.user_name),
            product_name: decryptData(transaction.product_name)
        }));

        res.json(decryptedResults);
    });
});


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

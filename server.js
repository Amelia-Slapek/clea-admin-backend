const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(cors({
    origin: [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:5173',
        'https://polite-tree-03a504103.6.azurestaticapps.net'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Połączono z MongoDB (Content Creators App)'))
    .catch(err => console.error('Błąd połączenia z MongoDB:', err));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});
const ImageSchema = new mongoose.Schema({
    imageData: { type: String, required: true },
    imageType: { type: String, enum: ['product', 'avatar', 'article'], required: true },
    createdAt: { type: Date, default: Date.now }
});
const Image = mongoose.model('Image', ImageSchema);
const CreatorSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    avatarImageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', default: null },
    isVerified: { type: Boolean, default: false },
    role: { type: String, default: 'creator' },
    createdAt: { type: Date, default: Date.now }
});
const Creator = mongoose.model('Creator', CreatorSchema);

const TempCreatorSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    verificationToken: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const TempCreator = mongoose.model('TempCreator', TempCreatorSchema);

const VerificationTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Creator', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);
const PasswordResetTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Creator', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const PasswordResetToken = mongoose.model('PasswordResetToken', PasswordResetTokenSchema);

const IngredientSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, unique: true },
    safetyLevel: { type: String, required: true, enum: ['bezpieczny', 'akceptowalny', 'lepiej unikać', 'niebezpieczny'] },
    origin: { type: String, required: true, enum: ['naturalne', 'syntetyczne', 'naturalne/syntetyczne'] },
    description: { type: String, required: true, trim: true },
    tags: { type: [String], default: [] },
    createdAt: { type: Date, default: Date.now }
});
const Ingredient = mongoose.model('Ingredient', IngredientSchema);

const ReviewSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true },
    content: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const Review = mongoose.model('Review', ReviewSchema);

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    brand: { type: String, trim: true },
    category: { type: String, trim: true },
    subcategory: { type: String, trim: true },
    skinType: [{ type: String, trim: true }],
    purpose: { type: String, trim: true },
    description: { type: String, trim: true },
    imageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', default: null },
    rating: { type: Number, default: 0 },
    reviews: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Review', default: [] }],
    ingredients: [{ type: mongoose.Schema.Types.ObjectId, ref: "Ingredient" }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

ProductSchema.pre('save', function (next) { this.updatedAt = Date.now(); next(); });
const Product = mongoose.model('Product', ProductSchema);

const TagConflictSchema = new mongoose.Schema({
    tag1: { type: String, required: true, trim: true, lowercase: true },
    tag2: { type: String, required: true, trim: true, lowercase: true },
    level: { type: String, enum: ["lekki konflikt", "silny konflikt", "zakazany"], required: true },
    description: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
const TagConflict = mongoose.model('TagConflict', TagConflictSchema);

const ArticleBlockSchema = new mongoose.Schema({
    article_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', required: true },
    type: { type: String, required: true },
    content: { type: mongoose.Schema.Types.Mixed, required: true },
    order_position: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now }
});
const ArticleBlock = mongoose.model('ArticleBlock', ArticleBlockSchema);

const ArticleSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    author_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Creator', required: true },
    coverImageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', required: true },
    category: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now }
});
const Article = mongoose.model('Article', ArticleSchema);

const DEFAULT_AVATAR_OBJECT_ID = new mongoose.Types.ObjectId('691d02a135df80c6f8b7ba66');

const isValidBase64Image = (base64) => {
    return typeof base64 === 'string' && base64.startsWith('data:image/') && base64.includes(';base64,');
};

const sendVerificationEmail = async (email, token, firstName) => {
    const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3000').replace(/\/$/, '');
    const verificationUrl = `${frontendUrl}/verify-email/${token}`;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Weryfikacja konta Twórcy Treści - Clea',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                <h2 style="color: #667eea;">Weryfikacja adresu email</h2>
                <p>Cześć ${firstName}!</p>
                <p>Dziękujemy za rejestrację. Aby dokończyć proces rejestracji, kliknij w poniższy przycisk (link ważny przez 1 godzinę):</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${verificationUrl}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Zweryfikuj adres email</a>
                </div>
                <p>Jeśli to nie Ty zarejestrowałeś się w naszej aplikacji, zignoruj tę wiadomość.</p>
            </div>
        `
    };
    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Błąd wysyłania emaila:', error);
        return false;
    }
};
const sendPasswordResetEmail = async (email, token, firstName) => {
    const frontendUrl = (process.env.FRONTEND_URL || 'http://localhost:3001').replace(/\/$/, '');

    const resetUrl = `${frontendUrl}/reset-password/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Resetowanie hasła - Panel Twórcy Clea',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                <h2 style="color: #667eea;">Resetowanie hasła</h2>
                <p>Cześć ${firstName},</p>
                <p>Otrzymaliśmy prośbę o zresetowanie hasła do Twojego panelu twórcy..</p>
                <p>Aby ustawić nowe hasło, kliknij w poniższy przycisk (link ważny przez 1 godzinę):</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetUrl}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Zresetuj hasło</a>
                </div>
                <p>Jeśli to nie Ty wysłałeś tę prośbę, możesz zignorować tę wiadomość.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Błąd wysyłania emaila resetującego:', error);
        return false;
    }
};
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Brak tokenu dostępu' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Nieprawidłowy token' });
        req.user = user;
        next();
    });
};
app.get('/api/ping', (req, res) => {
    try {
        res.status(200).json({ message: 'pong' });
    } catch (error) {
        console.error('Ping endpoint error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;

        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
        }

        const emailLower = email.toLowerCase();
        const existingCreator = await Creator.findOne({ email: emailLower });
        if (existingCreator) {
            return res.status(400).json({ message: 'Twórca o takim emailu już istnieje.' });
        }

        const existingTempCreator = await TempCreator.findOne({ email: emailLower });
        if (existingTempCreator) {
            return res.status(409).json({
                success: false,
                message: 'Konto zostało utworzone, ale niezweryfikowane.',
                requiresVerification: true,
                email: existingTempCreator.email
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tempCreator = new TempCreator({
            email: emailLower,
            password: hashedPassword,
            firstName,
            lastName,
            verificationToken
        });

        await tempCreator.save();

        const emailSent = await sendVerificationEmail(emailLower, verificationToken, firstName);

        if (!emailSent) {
            await TempCreator.findByIdAndDelete(tempCreator._id);
            return res.status(500).json({ message: 'Błąd wysyłania emaila weryfikacyjnego.' });
        }

        res.status(201).json({
            success: true,
            message: 'Link weryfikacyjny został wysłany. Sprawdź email.',
            requiresVerification: true
        });

    } catch (error) {
        console.error('Błąd rejestracji:', error);
        res.status(500).json({ message: 'Błąd serwera podczas rejestracji' });
    }
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;
        const tempCreator = await TempCreator.findOne({ verificationToken: token });

        if (!tempCreator) {
            return res.status(400).json({ message: 'Link weryfikacyjny wygasł lub jest nieprawidłowy.' });
        }

        const newCreator = new Creator({
            email: tempCreator.email,
            password: tempCreator.password,
            firstName: tempCreator.firstName,
            lastName: tempCreator.lastName,
            avatarImageId: DEFAULT_AVATAR_OBJECT_ID,
            isVerified: true
        });

        await newCreator.save();
        await TempCreator.findByIdAndDelete(tempCreator._id);

        const jwtToken = jwt.sign(
            { userId: newCreator._id, email: newCreator.email },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Konto twórcy zweryfikowane pomyślnie!',
            token: jwtToken,
            user: {
                id: newCreator._id,
                email: newCreator.email,
                firstName: newCreator.firstName,
                lastName: newCreator.lastName,
                isVerified: true
            }
        });

    } catch (error) {
        console.error('Błąd weryfikacji:', error);
        res.status(500).json({ message: 'Błąd serwera podczas weryfikacji.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email i hasło są wymagane' });
        const emailLower = email.toLowerCase();
        let creator = await Creator.findOne({ email: emailLower }).populate('avatarImageId');
        let isTemp = false;

        if (!creator) {
            creator = await TempCreator.findOne({ email: emailLower });
            isTemp = true;
        }

        if (!creator) return res.status(400).json({ message: 'Nieprawidłowy email lub hasło' });

        const isPasswordValid = await bcrypt.compare(password, creator.password);
        if (!isPasswordValid) return res.status(400).json({ message: 'Nieprawidłowy email lub hasło' });
        if (isTemp || creator.isVerified === false) {
            return res.status(403).json({
                message: 'Konto niezweryfikowane. Sprawdź email.',
                requiresVerification: true,
                email: creator.email
            });
        }

        const token = jwt.sign(
            { userId: creator._id, email: creator.email },
            process.env.JWT_SECRET,
            { expiresIn: '12h' }
        );

        res.json({
            message: 'Zalogowano pomyślnie',
            token,
            user: {
                id: creator._id,
                email: creator.email,
                firstName: creator.firstName,
                lastName: creator.lastName,
                avatarImageId: creator.avatarImageId?._id || null,
                avatarImageData: creator.avatarImageId?.imageData || null,
            }
        });
    } catch (error) {
        console.error('Błąd logowania:', error);
        res.status(500).json({ message: 'Błąd serwera podczas logowania' });
    }
});

app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ message: 'Email jest wymagany' });

        const emailLower = email.toLowerCase();
        const tempCreator = await TempCreator.findOne({ email: emailLower });

        if (tempCreator) {
            const newVerificationToken = crypto.randomBytes(32).toString('hex');
            tempCreator.verificationToken = newVerificationToken;
            tempCreator.createdAt = new Date();
            await tempCreator.save();

            const emailSent = await sendVerificationEmail(tempCreator.email, newVerificationToken, tempCreator.firstName);

            if (emailSent) {
                return res.json({ message: 'Email weryfikacyjny został wysłany ponownie.' });
            } else {
                return res.status(500).json({ message: 'Błąd wysyłania emaila.' });
            }
        }
        return res.status(404).json({ message: 'Nie znaleziono oczekującej rejestracji dla tego adresu email.' });

    } catch (error) {
        console.error('Błąd resend-verification:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/auth/verify-token', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: { id: req.user.userId, email: req.user.email }
    });
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Proszę podać adres email' });
        }
        const creator = await Creator.findOne({ email: email.toLowerCase() });

        if (!creator) {
            return res.json({ message: 'Jeśli podany email istnieje w bazie, wysłaliśmy na niego link resetujący.' });
        }
        await PasswordResetToken.deleteMany({ userId: creator._id });
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenDoc = new PasswordResetToken({
            userId: creator._id,
            token: resetToken
        });
        await tokenDoc.save();

        const emailSent = await sendPasswordResetEmail(creator.email, resetToken, creator.firstName);

        if (!emailSent) {
            return res.status(500).json({ message: 'Wystąpił błąd podczas wysyłania emaila.' });
        }

        res.json({ message: 'Jeśli podany email istnieje w bazie, wysłaliśmy na niego link resetujący.' });

    } catch (error) {
        console.error('Błąd resetowania hasła:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Brakujące dane.' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'Hasło musi mieć co najmniej 8 znaków.' });
        }
        const resetTokenDoc = await PasswordResetToken.findOne({ token });

        if (!resetTokenDoc) {
            return res.status(400).json({ message: 'Link resetujący jest nieprawidłowy lub wygasł.' });
        }

        const creator = await Creator.findById(resetTokenDoc.userId);
        if (!creator) {
            return res.status(404).json({ message: 'Użytkownik nie istnieje.' });
        }
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        creator.password = hashedPassword;
        await creator.save();
        await PasswordResetToken.findByIdAndDelete(resetTokenDoc._id);

        res.json({ message: 'Hasło zostało zmienione pomyślnie. Możesz się teraz zalogować.' });

    } catch (error) {
        console.error('Błąd zmiany hasła:', error);
        res.status(500).json({ message: 'Błąd serwera podczas zmiany hasła.' });
    }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            avatarBase64,
            currentPassword,
            newPassword
        } = req.body;

        const creator = await Creator.findById(req.user.userId);
        if (!creator) {
            return res.status(404).json({ message: 'Twórca nie znaleziony' });
        }

        const updateData = {};

        if (currentPassword || newPassword) {
            if (!currentPassword || !newPassword) {
                return res.status(400).json({
                    message: 'Aby zmienić hasło, musisz podać bieżące i nowe hasło.'
                });
            }

            const isPasswordValid = await bcrypt.compare(currentPassword, creator.password);
            if (!isPasswordValid) {
                return res.status(400).json({
                    message: 'Bieżące hasło jest nieprawidłowe'
                });
            }

            if (newPassword.length < 8) {
                return res.status(400).json({
                    message: 'Nowe hasło musi mieć co najmniej 8 znaków'
                });
            }

            const saltRounds = 10;
            updateData.password = await bcrypt.hash(newPassword, saltRounds);
        }

        if (firstName !== undefined) updateData.firstName = firstName.trim();
        if (lastName !== undefined) updateData.lastName = lastName.trim();

        if (email !== undefined && email.trim().toLowerCase() !== creator.email) {
            const existingCreator = await Creator.findOne({
                email: email.trim().toLowerCase(),
                _id: { $ne: req.user.userId }
            });
            if (existingCreator) {
                return res.status(400).json({
                    message: 'Ten email jest już używany przez innego twórcę'
                });
            }
            updateData.email = email.trim().toLowerCase();
        }

        if (avatarBase64 !== undefined) {
            if (avatarBase64 === null || avatarBase64 === '') {
                if (creator.avatarImageId && creator.avatarImageId.toString() !== DEFAULT_AVATAR_OBJECT_ID.toString()) {
                    await Image.findByIdAndDelete(creator.avatarImageId);
                }
                updateData.avatarImageId = DEFAULT_AVATAR_OBJECT_ID;
            }
            else if (isValidBase64Image(avatarBase64)) {
                if (creator.avatarImageId && creator.avatarImageId.toString() !== DEFAULT_AVATAR_OBJECT_ID.toString()) {
                    await Image.findByIdAndDelete(creator.avatarImageId);
                }
                const newAvatar = new Image({
                    imageData: avatarBase64,
                    imageType: 'avatar'
                });
                await newAvatar.save();
                updateData.avatarImageId = newAvatar._id;
            } else {
                return res.status(400).json({
                    message: 'Nieprawidłowy format zdjęcia profilowego'
                });
            }
        }

        const updatedCreator = await Creator.findByIdAndUpdate(
            req.user.userId,
            updateData,
            { new: true }
        ).populate('avatarImageId');

        res.json({
            message: 'Profil zaktualizowany pomyślnie',
            user: {
                id: updatedCreator._id,
                email: updatedCreator.email,
                firstName: updatedCreator.firstName,
                lastName: updatedCreator.lastName,
                isVerified: updatedCreator.isVerified,
                avatarImageId: updatedCreator.avatarImageId?._id || null,
                avatarImageData: updatedCreator.avatarImageId?.imageData || null
            }
        });
    } catch (error) {
        console.error('Błąd aktualizacji profilu:', error);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji profilu' });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find()
            .populate('imageId')
            .populate('reviews')
            .populate('ingredients', 'name safetyLevel')
            .sort({ createdAt: -1 });

        const productsWithImages = products.map(product => ({
            ...product.toObject(),
            imageData: product.imageId?.imageData || null,
            reviewCount: product.reviews ? product.reviews.length : 0
        }));

        res.json(productsWithImages);
    } catch (error) {
        console.error("Błąd pobierania produktów:", error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});
app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Nieprawidłowy ID' });

        const product = await Product.findById(id)
            .populate('ingredients')
            .populate('imageId')
            .populate({
                path: 'reviews',
                populate: { path: 'userId', select: 'username' }
            });

        if (!product) return res.status(404).json({ message: 'Nie znaleziono' });

        const productWithImage = {
            ...product.toObject(),
            imageData: product.imageId?.imageData || null
        };
        res.json(productWithImage);
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/products', async (req, res) => {
    try {
        const { name, brand, category, subcategory, skinType, purpose, description, imageBase64, ingredients } = req.body;

        if (!name) return res.status(400).json({ message: 'Nazwa (name) jest wymagana' });

        let imageId = null;
        if (imageBase64 && isValidBase64Image(imageBase64)) {
            const img = new Image({ imageData: imageBase64, imageType: 'product' });
            await img.save();
            imageId = img._id;
        }

        let processedIngredients = [];
        if (ingredients && Array.isArray(ingredients)) {
            processedIngredients = ingredients.filter(id => mongoose.Types.ObjectId.isValid(id));
            const count = await Ingredient.countDocuments({ _id: { $in: processedIngredients } });
            if (count !== processedIngredients.length) {
                return res.status(400).json({ message: 'Jeden lub więcej składników nie istnieje w bazie.' });
            }
        }

        const newProduct = new Product({
            name: name.trim(),
            brand,
            category,
            subcategory,
            skinType,
            purpose,
            description,
            imageId,
            ingredients: processedIngredients
        });

        await newProduct.save();
        res.status(201).json({ message: 'Produkt dodany', product: newProduct });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});
app.put('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, brand, category, subcategory, skinType, purpose, description, imageBase64, ingredients } = req.body;

        const product = await Product.findById(id);
        if (!product) return res.status(404).json({ message: 'Nie znaleziono' });

        if (imageBase64 !== undefined) {
            if (imageBase64 === null || imageBase64 === '') {
                if (product.imageId) await Image.findByIdAndDelete(product.imageId);
                product.imageId = null;
            } else if (isValidBase64Image(imageBase64)) {
                if (product.imageId) await Image.findByIdAndDelete(product.imageId);
                const img = new Image({ imageData: imageBase64, imageType: 'product' });
                await img.save();
                product.imageId = img._id;
            }
        }

        product.name = name;
        product.brand = brand;
        product.category = category;
        product.subcategory = subcategory;
        product.skinType = skinType;
        product.purpose = purpose;
        product.description = description;

        if (ingredients) {
            const validIds = ingredients.filter(id => mongoose.Types.ObjectId.isValid(id));
            product.ingredients = validIds;
        }

        await product.save();
        res.json({ message: 'Zaktualizowano' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const product = await Product.findById(id);
        if (!product) return res.status(404).json({ message: 'Nie znaleziono' });

        if (product.imageId) await Image.findByIdAndDelete(product.imageId);
        await Review.deleteMany({ productId: id });
        await Product.findByIdAndDelete(id);

        res.json({ message: 'Usunięto' });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/ingredients', async (req, res) => {
    const list = await Ingredient.find().sort({ name: 1 });
    res.json(list);
});

app.get('/api/ingredients/tags', async (req, res) => {
    const list = await Ingredient.find({}, 'tags');
    const tags = [...new Set(list.flatMap(i => i.tags))].sort();
    res.json(tags);
});

app.post('/api/ingredients', async (req, res) => {
    try {
        const { name, safetyLevel, origin, description, tags } = req.body;
        if (!name) return res.status(400).json({ message: 'Nazwa wymagana' });

        const newIng = new Ingredient({
            name: name.trim(), safetyLevel, origin, description, tags
        });
        await newIng.save();
        res.status(201).json({ message: 'Dodano', ingredient: newIng });
    } catch (error) {
        res.status(500).json({ message: 'Błąd' });
    }
});

app.delete('/api/ingredients/:id', async (req, res) => {
    await Ingredient.findByIdAndDelete(req.params.id);
    res.json({ message: 'Usunięto' });
});
app.put('/api/ingredients/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, safetyLevel, origin, description, tags } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                message: 'Nieprawidłowy ID składnika'
            });
        }

        if (!name || !safetyLevel || !origin || !description) {
            return res.status(400).json({
                message: 'Wszystkie pola są wymagane'
            });
        }

        const validSafetyLevels = ['bezpieczny', 'akceptowalny', 'lepiej unikać', 'niebezpieczny'];
        const validOrigins = ['naturalne', 'syntetyczne', 'naturalne/syntetyczne'];

        if (!validSafetyLevels.includes(safetyLevel)) {
            return res.status(400).json({
                message: 'Nieprawidłowy poziom bezpieczeństwa'
            });
        }

        if (!validOrigins.includes(origin)) {
            return res.status(400).json({
                message: 'Nieprawidłowe pochodzenie składnika'
            });
        }

        let processedTags = [];
        if (tags) {
            if (Array.isArray(tags)) {
                processedTags = tags
                    .map(tag => typeof tag === 'string' ? tag.trim().toLowerCase() : '')
                    .filter(tag => tag.length > 0);
            } else if (typeof tags === 'string') {
                processedTags = tags
                    .split(',')
                    .map(tag => tag.trim().toLowerCase())
                    .filter(tag => tag.length > 0);
            }
        }

        if (name.trim().toLowerCase() !== (await Ingredient.findById(id)).name.toLowerCase()) {
            const existingIngredient = await Ingredient.findOne({
                name: new RegExp(`^${name.trim()}$`, 'i'),
                _id: { $ne: id }
            });

            if (existingIngredient) {
                return res.status(400).json({
                    message: 'Składnik o tej nazwie już istnieje'
                });
            }
        }

        const updatedIngredient = await Ingredient.findByIdAndUpdate(
            id,
            {
                name: name.trim(),
                safetyLevel,
                origin,
                description: description.trim(),
                tags: processedTags
            },
            { new: true, runValidators: true }
        );

        if (!updatedIngredient) {
            return res.status(404).json({
                message: 'Składnik nie znaleziony'
            });
        }

        res.json({
            message: 'Składnik zaktualizowany pomyślnie',
            ingredient: updatedIngredient
        });

    } catch (error) {
        console.error('Błąd aktualizacji składnika:', error);
        res.status(500).json({
            message: 'Błąd serwera podczas aktualizacji składnika'
        });
    }
});
app.post('/api/cosmetics/analyze', async (req, res) => {
    const { composition } = req.body;
    if (!composition) return res.status(400).json({ message: 'Brak składu' });
    const names = composition.split(',').map(n => n.trim().toLowerCase()).filter(n => n);
    const found = await Ingredient.find({ name: { $in: names.map(n => new RegExp(`^${n}$`, 'i')) } });
    res.json({ identifiedIngredients: found.length, ingredients: found });
});

app.get('/api/tag-conflicts', async (req, res) => {
    try {
        const list = await TagConflict.find().sort({ createdAt: -1 });
        res.json(list);
    } catch (e) {
        res.status(500).json({ message: 'Błąd pobierania konfliktów' });
    }
});

app.post('/api/tag-conflicts', async (req, res) => {
    try {
        const { tag1, tag2, level, description } = req.body;

        if (!tag1 || !tag2 || !level) {
            return res.status(400).json({ message: 'Tagi i poziom są wymagane' });
        }

        const nc = new TagConflict({
            tag1: tag1.toLowerCase(),
            tag2: tag2.toLowerCase(),
            level,
            description
        });

        await nc.save();
        res.status(201).json({ message: 'Dodano konflikt', conflict: nc });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Błąd serwera podczas dodawania' });
    }
});

app.put('/api/tag-conflicts/:id', async (req, res) => {
    try {
        const { tag1, tag2, level, description } = req.body;

        const updated = await TagConflict.findByIdAndUpdate(
            req.params.id,
            {
                tag1: tag1?.toLowerCase(),
                tag2: tag2?.toLowerCase(),
                level,
                description,
                updatedAt: Date.now()
            },
            { new: true }
        );

        if (!updated) return res.status(404).json({ message: 'Nie znaleziono konfliktu' });
        res.json({ message: 'Zaktualizowano konflikt', conflict: updated });
    } catch (e) {
        res.status(500).json({ message: 'Błąd podczas aktualizacji' });
    }
});

app.delete('/api/tag-conflicts/:id', async (req, res) => {
    try {
        const deleted = await TagConflict.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ message: 'Nie znaleziono konfliktu' });
        res.json({ message: 'Usunięto konflikt' });
    } catch (e) {
        res.status(500).json({ message: 'Błąd podczas usuwania' });
    }
});

app.put('/api/articles/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, category, coverImageBase64, blocks } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID artykułu' });
        }

        if (!title || !title.trim()) {
            return res.status(400).json({ message: 'Tytuł jest wymagany' });
        }

        if (!category || !category.trim()) {
            return res.status(400).json({ message: 'Kategoria jest wymagana' });
        }

        if (!coverImageBase64 || !isValidBase64Image(coverImageBase64)) {
            return res.status(400).json({ message: 'Zdjęcie artykułu jest wymagane' });
        }

        if (!blocks || blocks.length === 0) {
            return res.status(400).json({ message: 'Artykuł musi zawierać co najmniej jeden blok' });
        }

        const article = await Article.findById(id);
        if (!article) return res.status(404).json({ message: 'Artykuł nie znaleziony' });

        if (article.author_id.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Brak uprawnień do edycji tego artykułu' });
        }

        const oldBlocks = await ArticleBlock.find({ article_id: id });
        const oldCoverImageId = article.coverImageId;

        if (oldCoverImageId) {
            await Image.findByIdAndDelete(oldCoverImageId);
        }

        for (const block of oldBlocks) {
            if (block.type === 'image' && block.content.imageId) {
                await Image.findByIdAndDelete(block.content.imageId);
            }
        }

        await ArticleBlock.deleteMany({ article_id: id });

        const coverImage = new Image({
            imageData: coverImageBase64,
            imageType: 'article'
        });
        await coverImage.save();

        article.title = title.trim();
        article.category = category.trim();
        article.coverImageId = coverImage._id;
        article.updatedAt = Date.now();
        await article.save();
        const savedBlocks = await Promise.all(
            blocks.map(async (block, index) => {
                let processedContent = block.content;

                if (block.type === 'image' && block.content.imageBase64) {
                    if (isValidBase64Image(block.content.imageBase64)) {
                        const blockImage = new Image({
                            imageData: block.content.imageBase64,
                            imageType: 'article'
                        });
                        await blockImage.save();

                        processedContent = {
                            imageId: blockImage._id,
                            altText: block.content.altText || ''
                        };
                    }
                }

                const newBlock = new ArticleBlock({
                    article_id: article._id,
                    type: block.type,
                    content: processedContent,
                    order_position: index
                });

                return await newBlock.save();
            })
        );

        const updatedArticle = await Article.findById(article._id)
            .populate('author_id', 'username firstName lastName')
            .populate('coverImageId');

        res.json({
            message: 'Artykuł zaktualizowany pomyślnie',
            article: {
                ...updatedArticle.toObject(),
                coverImageData: updatedArticle.coverImageId?.imageData || null,
                blocks: savedBlocks
            }
        });

    } catch (error) {
        console.error('Błąd aktualizacji:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/articles', async (req, res) => {
    const list = await Article.find()
        .populate('author_id', 'firstName lastName email')
        .populate('coverImageId')
        .sort({ createdAt: -1 });

    const mapped = list.map(a => ({ ...a.toObject(), coverImageData: a.coverImageId?.imageData || null }));
    res.json(mapped);
});

app.get('/api/articles/:id', async (req, res) => {
    const article = await Article.findById(req.params.id)
        .populate('author_id', 'firstName lastName')
        .populate('coverImageId');
    if (!article) return res.status(404).json({ message: 'Nie znaleziono' });

    const blocks = await ArticleBlock.find({ article_id: req.params.id }).sort({ order_position: 1 });
    const blocksImg = await Promise.all(blocks.map(async b => {
        if (b.type === 'image' && b.content.imageId) {
            const img = await Image.findById(b.content.imageId);
            return { ...b.toObject(), content: { ...b.content, imageData: img?.imageData } };
        }
        return b.toObject();
    }));

    res.json({ ...article.toObject(), coverImageData: article.coverImageId?.imageData, blocks: blocksImg });
});
app.post('/api/articles', authenticateToken, async (req, res) => {
    try {
        const { title, category, coverImageBase64, blocks } = req.body;
        const coverImg = new Image({ imageData: coverImageBase64, imageType: 'article' });
        await coverImg.save();

        const art = new Article({
            title,
            author_id: req.user.userId,
            coverImageId: coverImg._id,
            category
        });
        await art.save();

        for (let i = 0; i < blocks.length; i++) {
            let content = blocks[i].content;
            if (blocks[i].type === 'image' && blocks[i].content.imageBase64) {
                const bImg = new Image({ imageData: blocks[i].content.imageBase64, imageType: 'article' });
                await bImg.save();
                content = { imageId: bImg._id, altText: blocks[i].content.altText };
            }
            await new ArticleBlock({ article_id: art._id, type: blocks[i].type, content, order_position: i }).save();
        }
        res.status(201).json({ message: 'Utworzono artykuł' });
    } catch (e) {
        console.error(e);
        res.status(500).json({ message: 'Błąd tworzenia artykułu' });
    }
});

app.delete('/api/articles/:id', authenticateToken, async (req, res) => {
    const article = await Article.findById(req.params.id);
    if (article) {
        if (article.coverImageId) await Image.findByIdAndDelete(article.coverImageId);
        await ArticleBlock.deleteMany({ article_id: req.params.id });
        await Article.findByIdAndDelete(req.params.id);
    }
    res.json({ message: 'Usunięto' });
});
const PORT = process.env.PORT || 5001;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Serwer Admin CMS działa na porcie ${PORT}`);
});
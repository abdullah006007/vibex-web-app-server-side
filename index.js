const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const admin = require("firebase-admin");
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const multer = require('multer');

// Load env variables
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRETE,
});

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

const serviceAccount = require("./firebase_admin_key.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: "your-project-id.appspot.com",
});

const bucket = admin.storage().bucket();

// server.js (verifyFireBaseToken middleware)
const verifyFireBaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.error('verifyFireBaseToken: Missing Authorization header', { url: req.originalUrl });
        return res.status(401).send({ message: 'Unauthorized access', details: 'Missing Authorization header' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        console.error('verifyFireBaseToken: Missing token in Authorization header', { url: req.originalUrl });
        return res.status(401).send({ message: 'Unauthorized access', details: 'Missing token' });
    }
    try {
        const decoded = await admin.auth().verifyIdToken(token, true); // Check revocation
   
        req.decoded = decoded;
        next();
    } catch (error) {
        console.error('verifyFireBaseToken: Token verification failed', {
            url: req.originalUrl,
            error: error.message,
            code: error.code,
        });
        // Handle Firebase-specific errors
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).send({ message: 'Unauthorized access', details: 'Token expired' });
        }
        if (error.code === 'auth/invalid-id-token') {
            return res.status(401).send({ message: 'Unauthorized access', details: 'Invalid token' });
        }
        return res.status(403).send({ message: 'Unauthorized access', details: error.message });
    }
};

// MongoDB
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.kbhlw7l.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect();

        const db = client.db('vibeDb');
        const userCollection = db.collection('users');
        const postsCollection = db.collection('posts');
        const announcementCollection = db.collection('announcements');
        const reportsCollection = db.collection('reports');
        const notificationsCollection = db.collection('notifications');
        const tagsCollection = db.collection('tags');
        const connectionsCollection = db.collection('connections');

        // Stripe
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

        app.post('/create-payment-intent', async (req, res) => {
            try {
                const membershipPriceUSD = 10;
                let { price } = req.body;
                price = price ?? membershipPriceUSD;
                const parsedPrice = Number(price);
                if (isNaN(parsedPrice) || parsedPrice <= 0) {
                    return res.status(400).json({ error: 'Invalid price provided' });
                }
                const amountInCents = Math.round(parsedPrice * 100);
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amountInCents,
                    currency: 'usd',
                    automatic_payment_methods: { enabled: true },
                });
                res.json({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                console.error('❌ Error creating payment intent:', error.message);
                res.status(500).json({
                    error: 'Failed to create payment intent',
                    details: error.message,
                });
            }
        });

        app.post('/user/membership/upgrade', verifyFireBaseToken, async (req, res) => {
            try {
                const { paymentIntentId } = req.body;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
                if (paymentIntent.status !== 'succeeded') {
                    return res.status(400).json({ error: 'Payment not successful' });
                }
                const result = await userCollection.updateOne(
                    { email: decodedEmail },
                    {
                        $set: {
                            subscription: 'premium',
                            Badge: 'Gold',
                            membershipUpdatedAt: new Date().toISOString()
                        }
                    }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'User not found' });
                }
                res.json({ message: 'Membership upgraded to Premium with Gold badge' });
            } catch (error) {
                console.error('Error upgrading membership:', error);
                res.status(500).json({ error: 'Failed to upgrade membership' });
            }
        });

        app.post('/users', async (req, res) => {
            try {
                const { email, name } = req.body;
                if (!email) {
                    return res.status(400).json({ message: 'Email is required' });
                }
                const normalizedEmail = email.toLowerCase().trim();
                const userExist = await userCollection.findOne({
                    email: { $regex: new RegExp(`^${normalizedEmail}$`, 'i') }
                });
                if (userExist) {
                    return res.status(200).json({ message: 'User already exists', inserted: false });
                }
                const now = new Date().toISOString();
                const user = {
                    username: name || 'Anonymous',
                    email: normalizedEmail,
                    role: 'user',
                    subscription: 'free',
                    Badge: 'Bronze',
                    created_at: now,
                    last_log_in: now,
                };
                const result = await userCollection.insertOne(user);
                res.status(201).json({ message: 'User created successfully', insertedId: result.insertedId });
            } catch (error) {
                console.error('Error inserting user:', error);
                res.status(500).json({ message: `Failed to add user: ${error.message}` });
            }
        });

        app.put('/users/update', verifyFireBaseToken, async (req, res) => {
            try {
                const { email, updates } = req.body;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                if (!email || !updates || email !== decodedEmail) {
                    return res.status(400).json({ success: false, message: 'Invalid request or unauthorized' });
                }
                const allowedUpdates = ['name', 'phone', 'address', 'photoURL', 'bio'];
                const updateFields = Object.keys(updates).filter(key => allowedUpdates.includes(key));
                if (updateFields.length === 0) {
                    return res.status(400).json({ success: false, message: 'No valid fields to update' });
                }
                const updateData = {};
                updateFields.forEach(field => {
                    updateData[field] = updates[field] || null;
                });
                const result = await userCollection.updateOne(
                    { email: decodedEmail },
                    { $set: updateData }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ success: false, message: 'User not found' });
                }
                res.json({ success: true, message: 'Profile updated successfully' });
            } catch (error) {
                console.error('Error updating user profile:', error);
                res.status(500).json({ success: false, message: 'Failed to update profile' });
            }
        });

        app.post('/user/post/:uid', verifyFireBaseToken, async (req, res) => {
            try {
                const uid = req.params.uid;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                const {
                    authorImage,
                    authorName,
                    authorEmail,
                    postTitle,
                    postDescription,
                    postPhoto,
                    tag,
                    upVote,
                    downVote,
                } = req.body;
                const user = await userCollection.findOne({ email: decodedEmail });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                if (user.subscription !== 'premium' && user.role !== 'admin') {
                    const postCount = await postsCollection.countDocuments({ userId: uid });
                    if (postCount >= 5) {
                        return res.status(403).json({
                            error: 'Free users are limited to 5 posts. Upgrade to Premium membership for unlimited posts.',
                        });
                    }
                }
                const postData = {
                    _id: new Date().getTime().toString(),
                    userId: uid,
                    authorImage: authorImage || '',
                    authorName: authorName || '',
                    authorEmail: authorEmail || '',
                    postTitle: postTitle || '',
                    postDescription: postDescription || '',
                    postPhoto: postPhoto || '',
                    tag: tag || '',
                    createdAt: new Date().toISOString(),
                    upVote: upVote || 0,
                    downVote: downVote || 0,
                    comments: [],
                };
                const result = await postsCollection.insertOne(postData);
                res.status(201).json({ message: 'Post created successfully', post: postData });
            } catch (error) {
                console.error('Error creating post:', error);
                res.status(500).json({ error: 'Failed to create post' });
            }
        });

        app.get('/users/subscription/:email', verifyFireBaseToken, async (req, res) => {
            try {
                const email = req.params.email.toLowerCase().trim();
                const user = await userCollection.findOne({ email });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                res.json({ subscription: user.subscription || 'free', Badge: user.Badge || 'Bronze' });
            } catch (error) {
                console.error('Error fetching user subscription:', error);
                res.status(500).json({ error: 'Failed to fetch user subscription' });
            }
        });

        app.put('/user/post/:postId/upvote', verifyFireBaseToken, async (req, res) => {
            try {
                const postId = req.params.postId;
                const result = await postsCollection.updateOne(
                    { _id: postId },
                    { $inc: { upVote: 1 } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post not found' });
                }
                res.json({ message: 'Upvoted successfully' });
            } catch (error) {
                console.error('Error upvoting post:', error);
                res.status(500).json({ error: 'Failed to upvote post' });
            }
        });

        app.put('/user/post/:postId/downvote', verifyFireBaseToken, async (req, res) => {
            try {
                const postId = req.params.postId;
                const result = await postsCollection.updateOne(
                    { _id: postId },
                    { $inc: { downVote: 1 } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post not found' });
                }
                res.json({ message: 'Downvoted successfully' });
            } catch (error) {
                console.error('Error downvoting post:', error);
                res.status(500).json({ error: 'Failed to downvote post' });
            }
        });

        app.post('/user/post/:postId/comment', verifyFireBaseToken, async (req, res) => {
            try {
                const postId = req.params.postId;
                const { comment, userName, userImage, userEmail } = req.body;
                if (!comment) {
                    return res.status(400).json({ error: 'Comment text is required' });
                }
                const commentData = {
                    _id: new ObjectId(),
                    text: comment,
                    userName: userName || 'Anonymous',
                    userImage: userImage || 'https://placehold.co/40x40',
                    userEmail: userEmail || '',
                    createdAt: new Date().toISOString(),
                    upVote: 0,
                    downVote: 0,
                    replies: []
                };
                const result = await postsCollection.updateOne(
                    { _id: postId },
                    { $push: { comments: commentData } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post not found' });
                }
                res.json({ message: 'Comment added successfully', comment: commentData });
            } catch (error) {
                console.error('Error adding comment:', error);
                res.status(500).json({ error: 'Failed to add comment' });
            }
        });

        app.put('/user/post/:postId/comment/:commentId/upvote', verifyFireBaseToken, async (req, res) => {
            try {
                const { postId, commentId } = req.params;
                let commentObjectId;
                try {
                    commentObjectId = new ObjectId(commentId);
                } catch (error) {
                    return res.status(400).json({ error: 'Invalid comment ID' });
                }
                const result = await postsCollection.updateOne(
                    { _id: postId, 'comments._id': commentObjectId },
                    { $inc: { 'comments.$.upVote': 1 } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post or comment not found' });
                }
                res.json({ message: 'Comment upvoted successfully' });
            } catch (error) {
                console.error('Error upvoting comment:', error);
                res.status(500).json({ error: 'Failed to upvote comment' });
            }
        });

        app.put('/user/post/:postId/comment/:commentId/downvote', verifyFireBaseToken, async (req, res) => {
            try {
                const { postId, commentId } = req.params;
                let commentObjectId;
                try {
                    commentObjectId = new ObjectId(commentId);
                } catch (error) {
                    return res.status(400).json({ error: 'Invalid comment ID' });
                }
                const result = await postsCollection.updateOne(
                    { _id: postId, 'comments._id': commentObjectId },
                    { $inc: { 'comments.$.downVote': 1 } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post or comment not found' });
                }
                res.json({ message: 'Comment downvoted successfully' });
            } catch (error) {
                console.error('Error downvoting comment:', error);
                res.status(500).json({ error: 'Failed to downvote comment' });
            }
        });

        app.post('/user/post/:postId/comment/:commentId/reply', verifyFireBaseToken, async (req, res) => {
            try {
                const postId = req.params.postId;
                const commentId = req.params.commentId;
                const { reply, userName, userImage, userEmail } = req.body;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                if (!reply) {
                    return res.status(400).json({ error: 'Reply text is required' });
                }
                let commentObjectId;
                try {
                    commentObjectId = new ObjectId(commentId);
                } catch (error) {
                    return res.status(400).json({ error: 'Invalid comment ID' });
                }
                const post = await postsCollection.findOne({
                    _id: postId,
                    "comments._id": commentObjectId
                });
                if (!post) {
                    return res.status(404).json({ error: 'Post or comment not found' });
                }
                const replyData = {
                    _id: new ObjectId(),
                    text: reply.trim(),
                    userName: userName || 'Anonymous',
                    userImage: userImage || 'https://placehold.co/40x40',
                    userEmail: userEmail || decodedEmail || '',
                    createdAt: new Date().toISOString()
                };
                const result = await postsCollection.updateOne(
                    {
                        _id: postId,
                        "comments._id": commentObjectId
                    },
                    { $push: { "comments.$.replies": replyData } }
                );
                if (result.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to add reply' });
                }
                res.json({ message: 'Reply added successfully', reply: replyData });
            } catch (error) {
                console.error('Error adding reply:', error);
                res.status(500).json({ error: 'Failed to add reply', details: error.message });
            }
        });

        app.post('/user/post/:postId/comment/:commentId/report', verifyFireBaseToken, async (req, res) => {
            try {
                const { postId, commentId } = req.params;
                const { feedback } = req.body;
                const reporterEmail = req.decoded.email?.toLowerCase().trim();

                // Validate inputs
                if (!feedback || typeof feedback !== 'string' || feedback.trim() === '') {
                    return res.status(400).json({ error: 'Feedback is required and must be a non-empty string' });
                }
                if (!reporterEmail) {
                    return res.status(401).json({ error: 'Unauthorized: No email provided in token' });
                }

                // Validate commentId as ObjectId
                let commentObjectId;
                try {
                    commentObjectId = new ObjectId(commentId);
                } catch (error) {
                    return res.status(400).json({ error: 'Invalid comment ID', details: error.message });
                }

                // Check if post and comment exist
                const post = await postsCollection.findOne({
                    _id: postId,
                    'comments._id': commentObjectId,
                });
                if (!post) {
                    return res.status(404).json({ error: 'Post or comment not found' });
                }

                // Check for duplicate report
                const existingReport = await reportsCollection.findOne({
                    postId,
                    commentId: commentObjectId,
                    reporterEmail,
                });
                if (existingReport) {
                    return res.status(409).json({ error: 'You have already reported this comment' });
                }

                // Create report
                const reportData = {
                    postId,
                    commentId: commentObjectId,
                    feedback: feedback.trim(),
                    reporterEmail,
                    reportedAt: new Date().toISOString(),
                };
                const result = await reportsCollection.insertOne(reportData);

                res.status(201).json({ message: 'Comment reported successfully', reportId: result.insertedId });
            } catch (error) {
                console.error('Error reporting comment:', {
                    message: error.message,
                    stack: error.stack,
                    code: error.code,
                    name: error.name,
                });
                res.status(500).json({
                    error: 'Failed to report comment',
                    details: error.message || 'Internal server error',
                });
            }
        });



        app.get('/user/post/count/:id', async (req, res) => {
            try {
                const userId = req.params.id;
                const count = await postsCollection.countDocuments({ userId: userId });
                res.send({ count });
            } catch (error) {
                console.error("Error fetching post count:", error);
                res.status(500).send({ message: "Failed to fetch post count" });
            }
        });

        app.get('/user/posts/:id', async (req, res) => {
            try {
                const userId = req.params.id;
                const posts = await postsCollection
                    .find({ userId: userId })
                    .sort({ createdAt: -1 })
                    .toArray();
                res.send(posts);
            } catch (error) {
                console.error("Error fetching posts:", error);
                res.status(500).send({ message: "Failed to fetch posts" });
            }
        });

        app.get('/user/post/:postId', async (req, res) => {
            try {
                const { postId } = req.params;
                const post = await postsCollection.findOne({ _id: postId });
                if (!post) {
                    return res.status(404).json({ error: 'Post not found' });
                }
                res.json(post);
            } catch (error) {
                console.error('Error fetching post:', error);
                res.status(500).json({ error: 'Failed to fetch post' });
            }
        });

        app.get('/user/all-post', async (req, res) => {
            try {
                const sortType = req.query.sort || 'popularity';
                const page = Math.max(1, parseInt(req.query.page) || 1); // Default to page 1
                const limit = Math.max(1, parseInt(req.query.limit) || 10); // Default to 10 posts
                const skip = (page - 1) * limit; // Calculate skip for pagination

                let sortStage;
                if (sortType === 'newest') {
                    sortStage = { createdAt: -1 };
                } else {
                    sortStage = { voteDifference: -1, createdAt: -1 };
                }

                // Ensure postsCollection exists
                const collections = await db.listCollections({ name: 'posts' }).toArray();
                if (collections.length === 0) {
                    return res.status(404).json({ error: 'Posts collection not found', posts: [], totalCount: 0, currentPage: page, totalPages: 1 });
                }

                // Aggregation pipeline for fetching posts
                const pipeline = [
                    {
                        $addFields: {
                            voteDifference: { $subtract: ['$upVote', '$downVote'] },
                        },
                    },
                    { $sort: sortStage },
                    { $skip: skip },
                    { $limit: limit },
                ];

                // Fetch paginated posts
                const posts = await postsCollection.aggregate(pipeline).toArray();

                // Fetch total count of posts for pagination
                const totalCount = await postsCollection.countDocuments();

                res.json({
                    posts: posts || [],
                    totalCount: totalCount || 0,
                    currentPage: page,
                    totalPages: Math.ceil(totalCount / limit) || 1,
                });
            } catch (error) {
                console.error('Error fetching posts:', {
                    message: error.message,
                    stack: error.stack,
                    code: error.code,
                    name: error.name,
                });
                res.status(500).json({ error: 'Failed to fetch posts', details: error.message });
            }
        });


        app.delete('/user/post/:postId', verifyFireBaseToken, async (req, res) => {
            try {
                const { postId } = req.params;
                const userId = req.decoded.uid;
                if (!userId) return res.status(401).json({ error: 'User ID required' });
                const result = await postsCollection.deleteOne({
                    _id: postId,
                    userId: userId,
                });
                if (result.deletedCount === 0) {
                    return res.status(403).json({ error: 'Post not found or not authorized to delete' });
                }
                res.json({ message: 'Post deleted successfully' });
            } catch (error) {
                console.error(error);
                res.status(500).json({ error: 'Failed to delete post' });
            }
        });

        app.get('/users', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }

                const search = req.query.search || '';
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const skip = (page - 1) * limit;

                const query = search
                    ? { username: { $regex: search, $options: 'i' } }
                    : {};

                const users = await userCollection
                    .find(query)
                    .sort({ created_at: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                const totalCount = await userCollection.countDocuments(query);

                res.json({
                    users,
                    totalCount,
                    currentPage: page,
                    totalPages: Math.ceil(totalCount / limit),
                });
            } catch (error) {
                console.error('Error fetching users:', error);
                res.status(500).json({ error: 'Failed to fetch users', details: error.message });
            }
        });

        app.get('/users/role/:email', verifyFireBaseToken, async (req, res) => {
            try {
                const email = req.params.email.toLowerCase().trim();
                const user = await userCollection.findOne({ email });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                res.json({
                    subscription: user.subscription || 'free',
                    Badge: user.Badge || 'Bronze',
                    role: user.role || 'user',
                    name: user.name || user.username || 'Anonymous',
                    phone: user.phone || '',
                    address: user.address || '',
                    photoURL: user.photoURL || '',
                    bio: user.bio || ''
                });
            } catch (error) {
                console.error('Error fetching user subscription and role:', error);
                res.status(500).json({ error: 'Failed to fetch user subscription and role' });
            }
        });

        app.get('/user/post/count/:uid', verifyFireBaseToken, async (req, res) => {
            try {
                const uid = req.params.uid;
                const count = await postsCollection.countDocuments({ userId: uid });
                res.json({ count });
            } catch (error) {
                console.error('Error fetching post count:', error);
                res.status(500).json({ error: 'Failed to fetch post count' });
            }
        });

        app.get('/user/posts/:uid', verifyFireBaseToken, async (req, res) => {
            try {
                const uid = req.params.uid;
                const posts = await postsCollection.find({ userId: uid }).sort({ createdAt: -1 }).toArray();
                res.json(posts);
            } catch (error) {
                console.error('Error fetching posts:', error);
                res.status(500).json({ error: 'Failed to fetch posts' });
            }
        });

        app.get('/public-users', verifyFireBaseToken, async (req, res) => {
            try {
                const search = req.query.search || '';
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const skip = (page - 1) * limit;

                const query = search
                    ? { $or: [{ name: { $regex: search, $options: 'i' } }, { username: { $regex: search, $options: 'i' } }] }
                    : {};

                // Fetch paginated users
                const users = await userCollection
                    .find(query)
                    .sort({ created_at: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                // Get total count for pagination
                const totalCount = await userCollection.countDocuments(query);

                res.json({
                    users: users.map(user => ({
                        email: user.email,
                        name: user.name || user.username || 'Anonymous',
                        bio: user.bio || '',
                        photoURL: user.photoURL || '',
                        Badge: user.Badge || 'Bronze'
                    })),
                    totalCount,
                    currentPage: page,
                    totalPages: Math.ceil(totalCount / limit),
                });
            } catch (error) {
                console.error('Error fetching public users:', error);
                res.status(500).json({ error: 'Failed to fetch users' });
            }
        });


        app.post('/connections', verifyFireBaseToken, async (req, res) => {
            try {
                const { fromEmail, toEmail } = req.body;
                if (!fromEmail || !toEmail) {
                    return res.status(400).json({ error: 'Both fromEmail and toEmail are required' });
                }
                const existingConnection = await connectionsCollection.findOne({
                    $or: [
                        { fromEmail, toEmail },
                        { fromEmail: toEmail, toEmail: fromEmail }
                    ]
                });
                if (existingConnection) {
                    return res.status(409).json({ error: 'Connection request already exists' });
                }
                const connectionData = {
                    fromEmail,
                    toEmail,
                    status: 'pending',
                    createdAt: new Date().toISOString(),
                };
                await connectionsCollection.insertOne(connectionData);
                res.json({ message: 'Connection request sent' });
            } catch (error) {
                console.error('Error creating connection:', error);
                res.status(500).json({ error: 'Failed to create connection' });
            }
        });

        app.get('/connections/:email', verifyFireBaseToken, async (req, res) => {
            try {
                const email = req.params.email.toLowerCase().trim();
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                if (email !== decodedEmail) {
                    return res.status(403).json({ error: 'Unauthorized: Can only view own connections' });
                }
                const connections = await connectionsCollection.find({
                    $or: [
                        { fromEmail: email },
                        { toEmail: email }
                    ]
                }).toArray();
                res.json(connections);
            } catch (error) {
                console.error('Error fetching connections:', error);
                res.status(500).json({ error: 'Failed to fetch connections' });
            }
        });

        app.get('/reports', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                if (!userEmail) {
                    return res.status(401).json({ error: 'Unauthorized: No email provided in token' });
                }

                const user = await userCollection.findOne({ email: userEmail });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                if (user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }

                const page = Math.max(1, parseInt(req.query.page) || 1);
                const limit = Math.max(1, parseInt(req.query.limit) || 10); // Default to 10 reports
                const skip = (page - 1) * limit;

                // Ensure reportsCollection exists
                const collections = await db.listCollections({ name: 'reports' }).toArray();
                if (collections.length === 0) {
                    return res.status(404).json({ error: 'Reports collection not found' });
                }

                // Validate reportedAt field existence
                const reports = await reportsCollection
                    .find({ reportedAt: { $exists: true } }) // Ensure reportedAt exists
                    .sort({ reportedAt: -1 })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                const totalCount = await reportsCollection.countDocuments({ reportedAt: { $exists: true } });

                res.json({
                    reports: reports || [],
                    totalCount: totalCount || 0,
                    currentPage: page,
                    totalPages: Math.ceil(totalCount / limit) || 1,
                });
            } catch (error) {
                console.error('Error fetching reports:', {
                    message: error.message,
                    stack: error.stack,
                    code: error.code,
                    name: error.name,
                });
                res.status(500).json({
                    error: 'Failed to fetch reports',
                    details: error.message || 'Internal server error',
                });
            }
        });

        app.delete('/user/post/:postId/comment/:commentId', verifyFireBaseToken, async (req, res) => {
            try {
                const { postId, commentId } = req.params;
                const userEmail = req.decoded.email;
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                let commentObjectId;
                try {
                    commentObjectId = new ObjectId(commentId);
                } catch (error) {
                    return res.status(400).json({ error: 'Invalid comment ID' });
                }
                const result = await postsCollection.updateOne(
                    { _id: postId },
                    { $pull: { comments: { _id: commentObjectId } } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ error: 'Post or comment not found' });
                }
                await reportsCollection.deleteMany({ postId, commentId: commentObjectId });
                res.json({ message: 'Comment deleted successfully' });
            } catch (error) {
                console.error('Error deleting comment:', error);
                res.status(500).json({ error: 'Failed to delete comment' });
            }
        });

        app.patch('/users/make-admin/:id', verifyFireBaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const userEmail = req.decoded.email;
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const result = await userCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role: 'admin' } }
                );
                res.json({ message: 'User promoted to admin', result });
            } catch (error) {
                console.error('Error updating user role:', error);
                res.status(500).json({ error: 'Failed to update role' });
            }
        });

        app.patch('/users/remove-admin/:id', verifyFireBaseToken, async (req, res) => {
            const { id } = req.params;
            const loggedInEmail = req.decoded.email;
            try {
                const user = await userCollection.findOne({ email: loggedInEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const result = await userCollection.updateOne(
                    { _id: new ObjectId(id), email: { $ne: loggedInEmail } },
                    { $set: { role: 'user' } }
                );
                if (result.matchedCount === 0) {
                    return res.status(403).json({ message: "Cannot remove yourself or user not found" });
                }
                res.json({ message: "Admin removed successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Server error" });
            }
        });

        app.delete('/users/:id', verifyFireBaseToken, async (req, res) => {
            const userId = req.params.id;
            const adminEmail = req.decoded.email;
            try {
                const user = await userCollection.findOne({ email: adminEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const userToDelete = await userCollection.findOne({ _id: new ObjectId(userId) });
                if (!userToDelete) {
                    return res.status(404).json({ message: "User not found" });
                }
                if (userToDelete.role === "admin") {
                    return res.status(403).json({ message: "Cannot delete an admin" });
                }
                const result = await userCollection.deleteOne({ _id: new ObjectId(userId) });
                if (result.deletedCount === 1) {
                    return res.json({ message: "User deleted successfully" });
                } else {
                    return res.status(500).json({ message: "Failed to delete user" });
                }
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Server error" });
            }
        });

        app.post('/announcements', verifyFireBaseToken, upload.single('authorImage'), async (req, res) => {
            try {
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${decodedEmail}$`, 'i') } });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ message: 'Unauthorized: Admin access required' });
                }
                const { authorName, title, description } = req.body;
                if (!authorName || !title || !description) {
                    return res.status(400).json({ message: 'All fields (authorName, title, description) are required' });
                }
                let authorImage = "";
                if (!req.file) {
                    return res.status(400).json({ message: 'Author image is required' });
                }
                try {
                    const validImageTypes = ['image/jpeg', 'image/png', 'image/gif'];
                    if (!validImageTypes.includes(req.file.mimetype)) {
                        return res.status(400).json({ message: 'Invalid image type. Only JPEG, PNG, or GIF allowed.' });
                    }
                    if (req.file.size > 5 * 1024 * 1024) {
                        return res.status(400).json({ message: 'Image size exceeds 5MB limit.' });
                    }
                    const uploadResult = await new Promise((resolve, reject) => {
                        const stream = cloudinary.uploader.upload_stream(
                            { folder: 'announcements', resource_type: 'image' },
                            (error, result) => {
                                if (error) {
                                    return reject(new Error(`Cloudinary upload failed: ${error.message}`));
                                }
                                resolve(result);
                            }
                        );
                        streamifier.createReadStream(req.file.buffer).pipe(stream);
                    });
                    authorImage = uploadResult.secure_url;
                } catch (uploadError) {
                    return res.status(500).json({ message: `Failed to upload image to Cloudinary: ${uploadError.message}` });
                }
                const announcement = {
                    authorImage,
                    authorName: authorName.trim(),
                    title: title.trim(),
                    description: description.trim(),
                    createdAt: new Date().toISOString(),
                };
                const result = await announcementCollection.insertOne(announcement);
                const announcementId = result.insertedId;
                const users = await userCollection.find({ email: { $exists: true, $ne: null, $ne: '' } }).toArray();
                let successCount = 0;
                let failureCount = 0;
                for (const user of users) {
                    try {
                        const userEmail = user.email?.toLowerCase().trim();
                        if (!userEmail) {
                            failureCount++;
                            continue;
                        }
                        const filter = {
                            userEmail,
                            announcementId,
                        };
                        const update = {
                            $setOnInsert: {
                                title: announcement.title,
                                description: announcement.description,
                                authorImage: announcement.authorImage,
                                authorName: announcement.authorName,
                                createdAt: new Date().toISOString(),
                                read: false,
                            },
                        };
                        const notificationResult = await notificationsCollection.findOneAndUpdate(
                            filter,
                            update,
                            { upsert: true, returnDocument: 'after' }
                        );
                        if (!notificationResult.lastErrorObject?.updatedExisting) {
                            successCount++;
                        }
                    } catch (err) {
                        failureCount++;
                    }
                }
                res.status(201).json({
                    message: 'Announcement created successfully',
                    announcement: { ...announcement, _id: announcementId },
                    notifications: { success: successCount, failures: failureCount },
                });
            } catch (err) {
                console.error('Error creating announcement:', err);
                res.status(500).json({ message: `Failed to create announcement: ${err.message}` });
            }
        });

        app.post('/admin/resend-notifications', verifyFireBaseToken, async (req, res) => {
            try {
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                const user = await userCollection.findOne({ email: { $regex: new RegExp(`^${decodedEmail}$`, 'i') } });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ message: 'Unauthorized: Admin access required' });
                }
                const { announcementId } = req.body;
                if (!announcementId) {
                    return res.status(400).json({ message: 'announcementId is required' });
                }
                const announcement = await announcementCollection.findOne({ _id: new ObjectId(announcementId) });
                if (!announcement) {
                    return res.status(404).json({ message: 'Announcement not found' });
                }
                const users = await userCollection.find({ email: { $exists: true, $ne: null, $ne: '' } }).toArray();
                let successCount = 0;
                let failureCount = 0;
                for (const user of users) {
                    try {
                        const userEmail = user.email.toLowerCase().trim();
                        const filter = { userEmail, announcementId: new ObjectId(announcementId) };
                        const update = {
                            $setOnInsert: {
                                title: announcement.title,
                                description: announcement.description,
                                authorImage: announcement.authorImage,
                                createdAt: new Date().toISOString(),
                                read: false,
                            }
                        };
                        const notificationResult = await notificationsCollection.findOneAndUpdate(
                            filter,
                            { $setOnInsert: update },
                            { upsert: true, returnDocument: 'after' }
                        );
                        if (!notificationResult.lastErrorObject?.updatedExisting) {
                            successCount++;
                        }
                    } catch (err) {
                        failureCount++;
                    }
                }
                res.json({
                    message: 'Notifications resent successfully',
                    notifications: { success: successCount, failures: failureCount }
                });
            } catch (err) {
                console.error('Error resending notifications:', err);
                res.status(500).json({ message: `Failed to resend: ${err.message}` });
            }
        });

        app.get('/announcements', async (req, res) => {
            try {
                const announcements = await announcementCollection
                    .find()
                    .sort({ createdAt: -1 })
                    .toArray();
                res.json(announcements);
            } catch (err) {
                console.error('Error fetching announcements:', err);
                res.status(500).json({ message: 'Failed to fetch announcements' });
            }
        });

        app.delete('/announcements/:id', verifyFireBaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const userEmail = req.decoded.email;
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ message: 'Unauthorized: Admin access required' });
                }
                let announcementObjectId;
                try {
                    announcementObjectId = new ObjectId(id);
                } catch (error) {
                    return res.status(400).json({ message: 'Invalid announcement ID' });
                }
                const result = await announcementCollection.deleteOne({ _id: announcementObjectId });
                if (result.deletedCount === 0) {
                    return res.status(404).json({ message: 'Announcement not found' });
                }
                res.json({ message: 'Announcement deleted successfully' });
            } catch (err) {
                console.error('Error deleting announcement:', err);
                res.status(500).json({ message: 'Failed to delete announcement' });
            }
        });

        app.get('/notifications/:email', verifyFireBaseToken, async (req, res) => {
            try {
                const pathEmail = req.params.email.toLowerCase().trim();
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                if (pathEmail !== decodedEmail) {
                    return res.status(403).json({ message: 'Email mismatch - unauthorized' });
                }
                const { all } = req.query;
                const filter = { userEmail: pathEmail };
                if (all !== 'true') {
                    filter.read = false;
                }
                const notifications = await notificationsCollection
                    .find(filter)
                    .sort({ createdAt: -1 })
                    .toArray();
                res.json(notifications);
            } catch (err) {
                console.error('Error fetching notifications:', err);
                res.status(500).json({ message: `Failed to fetch notifications: ${err.message}` });
            }
        });

        app.patch('/notifications/:id/read', verifyFireBaseToken, async (req, res) => {
            try {
                const { id } = req.params;
                const userEmail = req.decoded.email?.toLowerCase().trim();
                let notificationObjectId;
                try {
                    notificationObjectId = new ObjectId(id);
                } catch (error) {
                    return res.status(400).json({ message: 'Invalid notification ID' });
                }
                const result = await notificationsCollection.updateOne(
                    { _id: notificationObjectId, userEmail },
                    { $set: { read: true } }
                );
                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: 'Notification not found' });
                }
                res.json({ message: 'Notification marked as read' });
            } catch (err) {
                console.error('Error marking notification as read:', err);
                res.status(500).json({ message: 'Failed to mark notification as read' });
            }
        });

        app.patch('/notifications/:email/read-all', verifyFireBaseToken, async (req, res) => {
            try {
                const pathEmail = req.params.email.toLowerCase().trim();
                const decodedEmail = req.decoded.email?.toLowerCase().trim();
                if (pathEmail !== decodedEmail) {
                    return res.status(403).json({ message: 'Email mismatch - unauthorized' });
                }
                const result = await notificationsCollection.updateMany(
                    { userEmail: pathEmail, read: false },
                    { $set: { read: true } }
                );
                res.json({ message: 'All notifications marked as read', modified: result.modifiedCount });
            } catch (err) {
                console.error('Error marking all as read:', err);
                res.status(500).json({ message: 'Failed to mark all as read' });
            }
        });

        app.get('/user/all-tags', async (req, res) => {
            try {
                const result = await postsCollection
                    .aggregate([
                        { $match: { tag: { $exists: true, $ne: '' } } },
                        { $group: { _id: '$tag' } },
                        { $sort: { _id: 1 } },
                        { $project: { tag: '$_id', _id: 0 } }
                    ])
                    .toArray();
                const tags = result
                    .map(doc => doc.tag)
                    .filter(tag => tag && typeof tag === 'string' && tag.trim() !== '')
                    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
                res.json(tags);
            } catch (error) {
                console.error('Error in /user/all-tags:', error);
                res.status(500).json({
                    error: 'Failed to fetch tags',
                    details: error.message,
                });
            }
        });

        app.get('/user/posts/diagnostic', async (req, res) => {
            try {
                const postCount = await postsCollection.countDocuments();
                const samplePosts = await postsCollection
                    .find({}, { projection: { _id: 1, tag: 1, createdAt: 1 } })
                    .limit(5)
                    .toArray();
                res.json({
                    postCount,
                    samplePosts,
                    message: 'Diagnostic info for posts collection',
                });
            } catch (error) {
                console.error('Error in posts diagnostic:', error);
                res.status(500).json({ error: 'Failed to fetch diagnostic info', details: error.message });
            }
        });

        app.get('/user/posts/search', async (req, res) => {
            try {
                const { tag } = req.query;
                if (!tag) {
                    return res.status(400).json({ error: 'Tag parameter is required' });
                }
                const normalizedTag = tag.trim().toLowerCase();
                const posts = await postsCollection
                    .find({
                        tag: {
                            $regex: `^${normalizedTag}$`,
                            $options: 'i'
                        }
                    })
                    .sort({ upVote: -1, createdAt: -1 })
                    .toArray();
                if (posts.length === 0) {
                    const partialMatchPosts = await postsCollection
                        .find({
                            tag: {
                                $regex: normalizedTag,
                                $options: 'i'
                            }
                        })
                        .sort({ upVote: -1, createdAt: -1 })
                        .toArray();
                    return res.json(partialMatchPosts);
                }
                res.json(posts);
            } catch (error) {
                console.error('Error in /user/posts/search:', error);
                res.status(500).json({
                    error: 'Failed to search posts',
                    details: error.message
                });
            }
        });

        app.get('/admin/profile', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                if (!userEmail) {
                    return res.status(400).json({ error: 'Email not provided in token' });
                }
                const user = await userCollection.findOne({ email: userEmail });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                if (user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const totalUsers = await userCollection.countDocuments();
                const totalPosts = await postsCollection.countDocuments();
                const commentsAggregate = await postsCollection
                    .aggregate([
                        { $match: { comments: { $exists: true, $ne: [] } } },
                        { $project: { commentCount: { $size: "$comments" } } },
                        { $group: { _id: null, totalComments: { $sum: "$commentCount" } } },
                    ])
                    .toArray();
                const totalComments = commentsAggregate.length > 0 ? commentsAggregate[0].totalComments : 0;
                const upVotesAggregate = await postsCollection.aggregate([
                    { $group: { _id: null, totalUpVotes: { $sum: "$upVote" } } }
                ]).toArray();
                const totalUpVotes = upVotesAggregate.length > 0 ? upVotesAggregate[0].totalUpVotes : 0;
                const downVotesAggregate = await postsCollection.aggregate([
                    { $group: { _id: null, totalDownVotes: { $sum: "$downVote" } } }
                ]).toArray();
                const totalDownVotes = downVotesAggregate.length > 0 ? downVotesAggregate[0].totalDownVotes : 0;
                const totalReports = await reportsCollection.countDocuments();
                const totalNotifications = await notificationsCollection.countDocuments();
                const totalAnnouncements = await announcementCollection.countDocuments();
                const totalAdmins = await userCollection.countDocuments({ role: 'admin' });
                const totalPremium = await userCollection.countDocuments({ subscription: 'premium' });
                const adminPosts = await postsCollection.countDocuments({ authorEmail: userEmail });
                const adminCommentsAggregate = await postsCollection
                    .aggregate([
                        { $unwind: { path: "$comments", preserveNullAndEmptyArrays: true } },
                        { $match: { "comments.userEmail": userEmail } },
                        { $count: "totalAdminComments" },
                    ])
                    .toArray();
                const adminComments = adminCommentsAggregate.length > 0 ? adminCommentsAggregate[0].totalAdminComments : 0;
                const thirtyDaysAgo = new Date();
                thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
                const recentPosts = await postsCollection.aggregate([
                    { $match: { createdAt: { $gte: thirtyDaysAgo.toISOString() } } },
                    {
                        $group: {
                            _id: { $dateToString: { format: "%Y-%m-%d", date: { $toDate: "$createdAt" } } },
                            posts: { $sum: 1 }
                        }
                    },
                    { $sort: { _id: 1 } },
                    { $project: { date: "$_id", posts: 1, _id: 0 } }
                ]).toArray();
                const recentUsers = await userCollection.aggregate([
                    { $match: { created_at: { $gte: thirtyDaysAgo.toISOString() } } },
                    {
                        $group: {
                            _id: { $dateToString: { format: "%Y-%m-%d", date: { $toDate: "$created_at" } } },
                            users: { $sum: 1 }
                        }
                    },
                    { $sort: { _id: 1 } },
                    { $project: { date: "$_id", users: 1, _id: 0 } }
                ]).toArray();
                const recentComments = await postsCollection.aggregate([
                    { $unwind: "$comments" },
                    { $match: { "comments.createdAt": { $gte: thirtyDaysAgo.toISOString() } } },
                    {
                        $group: {
                            _id: { $dateToString: { format: "%Y-%m-%d", date: { $toDate: "$comments.createdAt" } } },
                            comments: { $sum: 1 }
                        }
                    },
                    { $sort: { _id: 1 } },
                    { $project: { date: "$_id", comments: 1, _id: 0 } }
                ]).toArray();
                res.json({
                    name: user.username || 'Admin',
                    image: user.photoURL || 'https://via.placeholder.com/150',
                    email: user.email,
                    posts: adminPosts,
                    comments: adminComments,
                    users: totalUsers,
                    totalPosts,
                    totalComments,
                    totalUsers,
                    totalUpVotes,
                    totalDownVotes,
                    totalReports,
                    totalNotifications,
                    totalAnnouncements,
                    totalAdmins,
                    totalPremium,
                    recentActivity: {
                        posts: recentPosts,
                        users: recentUsers,
                        comments: recentComments
                    }
                });
            } catch (error) {
                console.error('Error fetching admin profile:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to fetch admin profile', details: error.message });
            }
        });

        app.post('/tags', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                if (!userEmail) {
                    return res.status(400).json({ error: 'Email not provided in token' });
                }
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const { name } = req.body;
                if (!name || typeof name !== 'string' || name.trim() === '') {
                    return res.status(400).json({ error: 'Valid tag name required' });
                }
                const normalizedTag = name.trim().toLowerCase();
                const existing = await tagsCollection.findOne({ name: normalizedTag });
                if (existing) {
                    return res.status(409).json({ error: 'Tag already exists' });
                }
                const result = await tagsCollection.insertOne({
                    name: normalizedTag,
                    createdAt: new Date().toISOString(),
                });
                res.status(201).json({ message: 'Tag added successfully', tag: normalizedTag });
            } catch (error) {
                console.error('Error adding tag:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to add tag', details: error.message });
            }
        });

        app.get('/tags', async (req, res) => {
            try {
                const tags = await tagsCollection.find().sort({ name: 1 }).toArray();
                res.json(tags.map((t) => t.name));
            } catch (error) {
                console.error('Error fetching tags:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to fetch tags', details: error.message });
            }
        });

        app.delete('/tags/:name', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                if (!userEmail) {
                    return res.status(400).json({ error: 'Email not provided in token' });
                }
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const tagName = req.params.name.trim().toLowerCase();
                if (!tagName) {
                    return res.status(400).json({ error: 'Tag name required' });
                }
                const result = await tagsCollection.deleteOne({ name: tagName });
                if (result.deletedCount === 0) {
                    return res.status(404).json({ error: 'Tag not found' });
                }
                res.json({ message: 'Tag deleted successfully' });
            } catch (error) {
                console.error('Error deleting tag:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to delete tag', details: error.message });
            }
        });

        app.get('/posts/search', async (req, res) => {
            try {
                const tag = req.query.tag?.trim().toLowerCase();
                if (!tag) {
                    return res.status(400).json({ error: 'Tag is required for search' });
                }
                const posts = await postsCollection.find({ tag }).toArray();
                if (posts.length === 0) {
                    return res.status(404).json({ message: 'No posts found for this tag' });
                }
                res.json(posts);
            } catch (error) {
                console.error('Error searching posts:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to search posts', details: error.message });
            }
        });

        app.get('/posts', async (req, res) => {
            try {
                const posts = await postsCollection.find().sort({ createdAt: -1 }).toArray();
                if (posts.length === 0) {
                    return res.status(404).json({ message: 'No posts found' });
                }
                res.json(posts);
            } catch (error) {
                console.error('Error fetching posts:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to fetch posts', details: error.message });
            }
        });


        app.get('/user/posts/count', async (req, res) => {
            try {
                const count = await Post.countDocuments({});
                res.json({ count });
            } catch (error) {
                res.status(500).json({ message: 'Failed to fetch posts count' });
            }
        });



        await client.db("admin").command({ ping: 1 });
       
    } finally {
        
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send(`server is running successfully`);
});

app.listen(port, () => {
    console.log(`server is running on ${port}`);
});
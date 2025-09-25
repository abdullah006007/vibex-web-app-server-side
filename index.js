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

const verifyFireBaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).send({ message: 'unauthorized access' });
    }
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded = decoded;
    } catch (error) {
        return res.status(403).send({ message: 'unauthorized access' });
    }
    next();
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






        //---------------------------------------------------stripe-----------------------------------------------


        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

        // Create Payment Intent (for /membership page)
        // create payment intent
        // ✅ create payment intent endpoint
        // ✅ create payment intent (simple style)
        app.post('/create-payment-intent', async (req, res) => {
            try {
                // You can optionally send price from frontend or hardcode membership price
                const membershipPriceUSD = 10; // $10 membership
                let { price } = req.body;

                // Use backend price if frontend price is missing
                price = price ?? membershipPriceUSD;

                // Convert price to a number and validate
                const parsedPrice = Number(price);
                if (isNaN(parsedPrice) || parsedPrice <= 0) {
                    return res.status(400).json({ error: 'Invalid price provided' });
                }

                // Convert dollars to cents (Stripe requires integer)
                const amountInCents = Math.round(parsedPrice * 100);

                // Create Stripe PaymentIntent
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: amountInCents,
                    currency: 'usd',
                    automatic_payment_methods: { enabled: true },
                });

                // Send client secret to frontend
                res.json({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                console.error('❌ Error creating payment intent:', error.message);
                res.status(500).json({
                    error: 'Failed to create payment intent',
                    details: error.message,
                });
            }
        });




        // Upgrade Membership (for /membership page)
        // Upgrade Membership (for /membership page)
        app.post('/user/membership/upgrade', verifyFireBaseToken, async (req, res) => {
            try {
                const { paymentIntentId } = req.body;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();

                // Verify payment intent
                const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
                if (paymentIntent.status !== 'succeeded') {
                    return res.status(400).json({ error: 'Payment not successful' });
                }

                // Update user membership status, subscription, and badge
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







        // User collection
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
                    role: 'user',                 // default
                    subscription: 'free',         // default
                    Badge: 'Bronze',              // default
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





        // Update User Profile
        app.put('/users/update', verifyFireBaseToken, async (req, res) => {
            try {
                const { email, updates } = req.body;
                const decodedEmail = req.decoded.email?.toLowerCase().trim();

                if (!email || !updates || email !== decodedEmail) {
                    return res.status(400).json({ success: false, message: 'Invalid request or unauthorized' });
                }

                const allowedUpdates = ['name', 'phone', 'address', 'photoURL'];
                const updateFields = Object.keys(updates).filter(key => allowedUpdates.includes(key));
                if (updateFields.length === 0) {
                    return res.status(400).json({ success: false, message: 'No valid fields to update' });
                }

                const updateData = {};
                updateFields.forEach(field => {
                    updateData[field] = updates[field] || null; // Allow null to clear fields
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



        // Post APIs
        // Post Creation API with Post Limit Check
        // Post Creation API with Post Limit Check
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

                // Check user membership and post count
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




        // Get User Subscription
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

        // Comment APIs
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

        // Reply API
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

                // Verify post and comment exist
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
                if (!feedback) {
                    return res.status(400).json({ error: 'Feedback is required' });
                }
                const reporterEmail = req.decoded.email;
                const reportData = {
                    postId,
                    commentId: new ObjectId(commentId),
                    feedback,
                    reporterEmail,
                    reportedAt: new Date().toISOString(),
                };
                const result = await reportsCollection.insertOne(reportData);
                res.status(201).json({ message: 'Comment reported successfully' });
            } catch (error) {
                console.error('Error reporting comment:', error);
                res.status(500).json({ error: 'Failed to report comment' });
            }
        });

        // Get count of posts by user
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

        // Get posts by user
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

        // Get a single post by ID
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

        // Get all posts with sorting support
        app.get('/user/all-post', async (req, res) => {
            try {
                const sortType = req.query.sort || 'popularity'; // Default to popularity
                let sortStage;

                if (sortType === 'newest') {
                    sortStage = { $sort: { createdAt: -1 } };
                } else {
                    // Popularity: voteDifference desc, then createdAt desc
                    sortStage = { $sort: { voteDifference: -1, createdAt: -1 } };
                }

                const pipeline = [
                    {
                        $addFields: {
                            voteDifference: { $subtract: ['$upVote', '$downVote'] },
                        },
                    },
                    sortStage,
                ];

                const result = await postsCollection.aggregate(pipeline).toArray();
                res.send(result);
            } catch (error) {
                console.error('Error fetching posts:', error);
                res.status(500).json({ error: 'Failed to fetch posts' });
            }
        });

        // Delete post
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

        // Get User Role


        // Get User Subscription and Role
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
                    role: user.role || 'user' // Include role in the response
                });
            } catch (error) {
                console.error('Error fetching user subscription and role:', error);
                res.status(500).json({ error: 'Failed to fetch user subscription and role' });
            }
        });


        // Get User Post Count
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
        // Get User Posts
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



        // Admin APIs
        app.get('/users', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email;
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const search = req.query.search || '';
                const query = search
                    ? { name: { $regex: search, $options: 'i' } }
                    : {};
                const users = await userCollection.find(query).toArray();
                res.json(users);
            } catch (error) {
                console.error('Error fetching users:', error);
                res.status(500).json({ error: 'Failed to fetch users' });
            }
        });

        app.get('/reports', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email;
                const user = await userCollection.findOne({ email: userEmail });
                if (!user || user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }
                const reports = await reportsCollection.find().sort({ reportedAt: -1 }).toArray();
                res.json(reports);
            } catch (error) {
                console.error('Error fetching reports:', error);
                res.status(500).json({ error: 'Failed to fetch reports' });
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

        // Announcement APIs
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

                // Notify all users
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

        // Tags APIs
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








        // API to get admin profile
        app.get('/admin/profile', verifyFireBaseToken, async (req, res) => {
            try {
                const userEmail = req.decoded.email?.toLowerCase().trim();
                if (!userEmail) {
                    return res.status(400).json({ error: 'Email not provided in token' });
                }

                // Fetch user
                const user = await userCollection.findOne({ email: userEmail });
                if (!user) {
                    return res.status(404).json({ error: 'User not found' });
                }
                if (user.role !== 'admin') {
                    return res.status(403).json({ error: 'Unauthorized: Admin access required' });
                }

                // Total users
                const totalUsers = await userCollection.countDocuments();

                // Total posts
                const totalPosts = await postsCollection.countDocuments();

                // Total comments
                const commentsAggregate = await postsCollection
                    .aggregate([
                        { $match: { comments: { $exists: true, $ne: [] } } },
                        { $project: { commentCount: { $size: "$comments" } } },
                        { $group: { _id: null, totalComments: { $sum: "$commentCount" } } },
                    ])
                    .toArray();
                const totalComments = commentsAggregate.length > 0 ? commentsAggregate[0].totalComments : 0;

                // Total upVotes (likes)
                const upVotesAggregate = await postsCollection.aggregate([
                    { $group: { _id: null, totalUpVotes: { $sum: "$upVote" } } }
                ]).toArray();
                const totalUpVotes = upVotesAggregate.length > 0 ? upVotesAggregate[0].totalUpVotes : 0;

                // Total downVotes (dislikes)
                const downVotesAggregate = await postsCollection.aggregate([
                    { $group: { _id: null, totalDownVotes: { $sum: "$downVote" } } }
                ]).toArray();
                const totalDownVotes = downVotesAggregate.length > 0 ? downVotesAggregate[0].totalDownVotes : 0;

                // Total reports
                const totalReports = await reportsCollection.countDocuments();

                // Total notifications
                const totalNotifications = await notificationsCollection.countDocuments();

                // Total announcements
                const totalAnnouncements = await announcementCollection.countDocuments();

                // Total admins
                const totalAdmins = await userCollection.countDocuments({ role: 'admin' });

                // Total premium users
                const totalPremium = await userCollection.countDocuments({ subscription: 'premium' });

                // Admin's posts
                const adminPosts = await postsCollection.countDocuments({ authorEmail: userEmail });

                // Admin's comments
                const adminCommentsAggregate = await postsCollection
                    .aggregate([
                        { $unwind: { path: "$comments", preserveNullAndEmptyArrays: true } },
                        { $match: { "comments.userEmail": userEmail } },
                        { $count: "totalAdminComments" },
                    ])
                    .toArray();
                const adminComments = adminCommentsAggregate.length > 0 ? adminCommentsAggregate[0].totalAdminComments : 0;

                // Recent activity (last 30 days)
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




        // API to add tag (admin only)
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

        // API to get all tags
        app.get('/tags', async (req, res) => {
            try {
                const tags = await tagsCollection.find().sort({ name: 1 }).toArray();
                res.json(tags.map((t) => t.name));
            } catch (error) {
                console.error('Error fetching tags:', error.message, error.stack);
                res.status(500).json({ error: 'Failed to fetch tags', details: error.message });
            }
        });



        // New backend API: app.delete('/tags/:name')
        // Add this new endpoint after the existing app.post('/tags', ...)
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







        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);

app.get('/', (req, res) => {
    res.send(`server is running successfully`);
});

app.listen(port, () => {
    console.log(`server is running on ${port}`);
});
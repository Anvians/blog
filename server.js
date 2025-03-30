const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(helmet());
// I will use this when put and head require
// app.use(cors({
//   origin: "http://localhost:3000", 
//   methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
//   credentials: true,
//   optionsSuccessStatus: 204,
// }));


app.use(cors({
  origin: "http://localhost:3000",
  methods: "GET, POST, PUT, DELETE",
  credentials: true,
}));
  

// MongoDB connection

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB.");

  // Start the server only after successful MongoDB connection
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});
//MongoDB schema
// Post schema

// Update the PostSchema to store embedded comments
const PostSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String, default: "" },
  media: { type: String, default: null },
  privacy: {
    type: String,
    enum: ["public", "friends", "only_me"],
    default: "public",
  },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  comments: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
      text: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
});

const Posts = mongoose.model("Post", PostSchema);

// User schema
const userSchema = new mongoose.Schema({
  firstname: { type: String, required: true },
  lastname: { type: String },
  username: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  dp: { type: String },
  bio: { type: String },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);

// Following schema
const followingSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true, // Indexing for faster lookups
    },
    followingId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true, // Indexing for efficient queries
    },
    followedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

followingSchema.index({ userId: 1, followingId: 1 }, { unique: true });

Following = mongoose.model("Following", followingSchema);

// Add following user API
app.post("/follow", authenticateToken, async (req, res) => {
  const { followingId } = req.body;
  if (!followingId) {
    return res
      .status(400)
      .json({ success: false, message: "Following user ID is required" });
  }

  try {
    const newFollow = new Following({
      userId: req.user.id,
      followingId,
    });

    await newFollow.save();
    res
      .status(201)
      .json({ success: true, message: "User followed successfully" });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "You are already following this user",
      });
    }
    console.error("Error following user:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// If i am following the user on not
app.get(
  "/following/check/:targetUserId",
  authenticateToken,
  async (req, res) => {
    try {
      const { targetUserId } = req.params;
      // Validate if targetUserId is a valid MongoDB ObjectId
      if (!mongoose.Types.ObjectId.isValid(targetUserId)) {
        return res
          .status(400)
          .json({ success: false, message: "Invalid target user ID" });
      }

      // Check if the logged-in user is following the target user
      const followingdata = await Following.findOne({
        userId: req.user.id,
        followingId: targetUserId,
      });

      // If no following data exists, return response that the user is not following the target user
      if (!followingdata) {
        return res
          .status(200)
          .json({ success: false, message: "You are not following this user" });
      }

      // Return response that the user is following the target user
      return res
        .status(200)
        .json({ success: true, message: "You are following this user" });
      // Validate if targetUserId is a valid MongoDB ObjectId
    } catch (err) {
      console.error("Error checking if following user:", err);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);


// Unfollow user API
app.post("/unfollow", authenticateToken, async (req, res) => {
  const { followingId } = req.body;
  if (!followingId) {
    return res
      .status(400)
      .json({ success: false, message: "Following user ID is required" });
  }

  try {
    const unfollow = await Following.findOneAndDelete({
      userId: req.user.id,
      followingId,
    });

    if (!unfollow) {
      return res
        .status(404)
        .json({ success: false, message: "You are not following this user" });
    }

    res
      .status(200)
      .json({ success: true, message: "User unfollowed successfully" });
  } catch (err) {
    console.error("Error unfollowing user:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Register user API
app.post("/register", async (req, res) => {
  const { firstname, lastname, username, password, email } = req.body;
  if (!firstname || !username || !password || !email) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "Username or email already exists" });
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        firstname,
        lastname,
        username,
        password: hashedPassword,
        email,
      });
      await newUser.save();
      res
        .status(201)
        .json({ success: true, message: "User registered successfully" });
    }
  } catch (err) {
    console.error("Error inserting data: " + err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Login user API
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).send("All fields are required");
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).send("Invalid credentials");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid credentials");
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({ success: true, message: "Login successful", token });
  } catch (err) {
    console.error("Error during login: " + err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Middleware to verify JWT token

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .json({ success: false, message: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ success: false, message: "Token missing" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error("JWT Verification Error:", err.message); // Log error for debugging
      return res.status(403).json({ success: false, message: "Invalid token" });
    }
    if (!decoded.id) {
      return res
        .status(403)
        .json({ success: false, message: "Invalid token payload" });
    }
    req.user = { id: decoded.id };
    next();
  });
}


// Upload file API
const multer = require("multer");
const path = require("path");

// Configure Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Store files in 'uploads' folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Rename file with timestamp
  },
});
const upload = multer({ storage: storage });

// Ensure 'uploads' folder exists
const fs = require("fs");
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Update profile API
app.post("/upload_dp", authenticateToken, upload.single("dp"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: "No file uploaded" });
    }

    // File path where the image is stored
    const dpPath = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
    // Assuming you have a User model, update the user's profile with the new image path
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id, // Use the user ID from the JWT token
      { dp: dpPath }, // Update dp with the new file path
      { new: true } // Return the updated user document
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
// Get user profile API

app.get("/userprofile", authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid user ID" });
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error("Error getting user profile:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




app.use(
    "/uploads",
    express.static(path.join(__dirname, "uploads"), {
      setHeaders: (res, path) => {
        res.set("Access-Control-Allow-Origin", "http://localhost:3000"); // Allow requests from your frontend
        res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
        res.set("Access-Control-Allow-Headers", "Origin, Content-Type, Accept");
      },
    })
  );
// Upload API (for MongoDB)
// app.post(
//     "/upload",
//     authenticateToken,
//     upload.single("file"),
//     async (req, res) => {
//       try {
//         if (!req.file) {
//           return res
//             .status(400)
//             .json({ success: false, message: "File is required" });
//         }
  
//         const { content, privacy } = req.body;
//         const userId = req.user.id; // Extracted from JWT token
  
//         // Normalize the file path to use forward slashes
//         const mediaPath = `uploads/${req.file.filename}`.replace(/\\/g, "/");
  
//         // Save post in MongoDB with the normalized image path
//         const newPost = new Posts({
//           user: userId,
//           content: content || "",
//           media: mediaPath, // Use normalized path
//           privacy: privacy || "public",
//         });
  
//         await newPost.save();
//         res.status(201).json({
//           success: true,
//           message: "Post uploaded successfully",
//           post: newPost,
//         });
//       } catch (err) {
//         console.error("Error uploading post:", err);
//         res.status(500).json({ success: false, message: "Server error" });
//       }
//     }
//   );

app.post(
    "/upload",
    authenticateToken,
    upload.single("file"),
    async (req, res) => {
      try {
        if (!req.file) {
          return res
            .status(400)
            .json({ success: false, message: "File is required" });
        }
  
        const { content, privacy } = req.body;
        const userId = req.user.id; // Extracted from JWT token
  
        const mediaUrl = `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}`;
  
        const newPost = new Posts({
          user: userId,
          content: content || "",
          media: mediaUrl, // Store full URL for React to use
          privacy: privacy || "public",
        });
  
        await newPost.save();
        res.status(201).json({
          success: true,
          message: "Post uploaded successfully",
          post: newPost,
        });
      } catch (err) {
        console.error("Error uploading post:", err);
        res.status(500).json({ success: false, message: "Server error" });
      }
    }
);


// GET Post data API
app.get("/media", authenticateToken, async (req, res) => {
  try {
    const posts = await Posts.find({ user: req.user.id });

    if (!posts || posts.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "No posts found" });

    }

    // Add full URL to each post
    const updatedPosts = posts.map((post) => ({
      ...post.toObject(),
      media: post.media
        ? `http://localhost:5000/${post.media.replace(/\\/g, "/")}`
        : null,
    }));

    res.status(200).json({ success: true, posts: updatedPosts });
  } catch (err) {
    console.error("Error getting posts:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get user by username API
app.post("/user", authenticateToken, async (req, res) => {
  const { searchUser } = req.body;
  if (!searchUser) {
    return res
      .status(400)
      .json({ success: false, message: "Username is required" });
  }

  try {
    const user = await User.findOne({ username: searchUser });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error("Error getting user:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// app.get('/home', authenticateToken, async(req, res)=>{

//     try{
//         const posts = await Posts.find().sort({ createdAt: -1 }).limit(10).populate('user', 'username dp').exec();

//         if (!posts || posts.length === 0) {
//             return res.status(404).json({ success: false, message: 'No posts found' });
//         }
//         console.log(posts)
//         res.status(200).json({ success: true, posts });
//     }catch(e){
//         console.error("Error occure", e)
//         res.status(500).json({ success : false, message: 'Server error' })
//     }

// })

app.get("/home", authenticateToken, async (req, res) => {
  try {
    const following = await Following.find({ userId: req.user.id })
      .select("followingId")
      .exec();
    const followingIds = following.map((f) => f.followingId);

    const posts = await Posts.find({ user: { $in: followingIds } })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate("user", "username dp")
      .exec();

    if (!posts || posts.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "No posts found" });
    }

    res.status(200).json({ success: true, posts });
  } catch (e) {
    console.error("Error occure", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
//Liked API
app.post("/like", authenticateToken, async (req, res) => {
  const { postId } = req.body;
  if (!postId) {
    return res.status(400).json({ success: false, message: "No post found" }); // Use return to stop further execution
  }

  try {
    const post = await Posts.findById(postId);
    // Check if the post exists
    if (!post) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found" });
    }

    // Check if the user has already liked the post
    const userIdIndex = post.likes.indexOf(req.user.id);

    if (userIdIndex !== -1) {
      // User has already liked the post, so remove their like (dislike)
      post.likes.splice(userIdIndex, 1);
    } else {
      // User has not liked the post, so add their like
      post.likes.push(req.user.id);
    }

    // Save the changes to the database (if using a database like MongoDB)
    await post.save();

    return res.status(200).json({ success: true, likes: post.likes });
  } catch (e) {
    console.error("Error liking post:", e);
    return res.status(500).json({ success: false, message: "Server error" }); // Use return here as well
  }
});

//comment API

const { body, validationResult } = require("express-validator");
const { log } = require("console");



app.post("/comment", authenticateToken, async (req, res) => {
  let { postId, comment } = req.body;

  // Validate postId
  if (!mongoose.Types.ObjectId.isValid(postId)) {
    return res.status(400).json({ success: false, message: "Invalid post ID" });
  }

  comment = comment.trim();
  
  if (!comment) {
    return res.status(400).json({ success: false, message: "Comment is required" });
  }

  try {
    const post = await Posts.findById(postId);
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    const newComment = {
      user: mongoose.Types.ObjectId(req.user.id),
      text: comment,
      createdAt: new Date(),
    };

    post.comments.push(newComment);
    await post.save();

    return res.status(201).json({
      success: true,
      message: "Comment added successfully",
      comment: newComment,
    });
  } catch (error) {
    console.error("Error adding comment:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get comments API
app.get("/comments/:postId", authenticateToken, async (req, res) => {
  const { postId } = req.params;

  // Validate postId
  if (!mongoose.Types.ObjectId.isValid(postId)) {
    return res.status(400).json({ success: false, message: "Invalid post ID" });
  }

  try {
    const post = await Posts.findById(postId).populate("comments.user", "username dp");
    if (!post) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    if (!post.comments || post.comments.length === 0) {
      return res.status(404).json({ success: false, message: "No comments found" });
    }

    return res.status(200).json({
      success: true,
      comments: post.comments,
    });
  } catch (error) {
    console.error("Error fetching comments:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});


//this API is to get the people i follow
app.get('/following', authenticateToken, async (req, res) => {
  try {
      // Check if the user ID is valid
      if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
          return res.status(400).json({ success: false, message: 'Invalid user ID' });
      }

      // Fetch the user's following data
      const followingData = await Following.find({ userId: req.user.id });

      // If the user doesn't follow anyone or no data is found
      

      // Now get the details of the users being followed (assuming you store user info in another model)

      // Respond with the list of followed users
      res.status(200).json({ success: true, following: followingData });
  } catch (err) {
      console.error('Error getting following data:', err);
      res.status(500).json({ success: false, message: 'Server error' });
  }
});



// This API is to get the people who follow me
app.get('/followers', authenticateToken, async (req, res) => {
  try {
    // Check if the user ID is valid
    if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // Fetch the followers of the user
    const followersData = await Following.find({ followingId: req.user.id });
    if (!followersData || followersData.length === 0) {
      return res.status(404).json({ success: false, message: 'No followers found' });
    }
    // Respond with the list of followers
    res.status(200).json({ success: true, followers: followersData });
  } catch (err) {
    console.error('Error getting followers data:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// This API is to get the data of the people i follow
app.post('/get-following-data', authenticateToken, async (req, res) => {
  
  try {
    const { followingIds } = req.body;

    if (!Array.isArray(followingIds) || followingIds.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "Following IDs are required" });
    }

    // Validate each ID in the array
    const validIds = followingIds.filter((id) =>
      mongoose.Types.ObjectId.isValid(id)
    );

    if (validIds.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No valid following IDs provided" });
    }

    // Fetch user data for the valid IDs
    const users = await User.find({ _id: { $in: validIds } }).select(
      "username dp bio firstname lastname email"
    );

    if (!users || users.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "No users found for the given IDs" });
    }

    res.status(200).json({ success: true, users });
  } catch (err) {
    console.error("Error fetching following data:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// This API is to get the data of the people who follow me
app.post('/get-followers-data', authenticateToken, async (req, res) => {
  try {
    const { followerIds } = req.body;

    // Validate the input
    if (!followerIds || !Array.isArray(followerIds) || followerIds.length === 0) {
      return res
        .status(400)
        
        .json({ success: false, message: "Follower IDs are required and must be an array" });
    }

    // Validate each ID in the array
    const validIds = followerIds.filter((id) => mongoose.Types.ObjectId.isValid(id));

    if (validIds.length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "No valid follower IDs provided" });
    }

    // Fetch user data for the valid IDs
    const users = await User.find({ _id: { $in: validIds } }).select(
      "username dp bio firstname lastname email"
    );

    if (!users || users.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "No users found for the given IDs" });
    }

    // Return the fetched user data
    res.status(200).json({ success: true, users });
  } catch (err) {
    console.error("Error fetching followers data:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/user/:username", authenticateToken, async (req, res) => {

  const { username } = req.params;

  try {
    const user = await User.findOne({ username }).select("_id username dp bio firstname lastname email");

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/postfollowing", authenticateToken, async (req, res) => {
  try {
    const userId = req.query.userId || req.user.id; // Get userId from query or token

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ success: false, message: "Invalid user ID" });
    }

    const followingData = await Following.find({ userId });

    res.status(200).json({ success: true, following: followingData });
  } catch (err) {
    console.error("Error getting following data:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// app.get('/postfollowers', authenticateToken, async (req, res) => {
//   try {
//     // Check if the user ID is valid
//     if (!mongoose.Types.ObjectId.isValid(req.user.id)) {
//       return res.status(400).json({ success: false, message: 'Invalid user ID' });
//     }

//     // Fetch the followers of the user
//     const followersData = await Following.find({ followingId: req.user.id });

//     if (!followersData || followersData.length === 0) {
//       return res.status(404).json({ success: false, message: 'No followers found' });
//     }
//     // Respond with the list of followers
//     res.status(200).json({ success: true, followers: followersData });
//   } catch (err) {
//     console.error('Error getting followers data:', err);
//     res.status(500).json({ success: false, message: 'Server error' });
//   }
// });

// Get user ID from username
app.get('/searchedfollowers/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;

  try {
    const user = await User.findOne({ username }).select("_id");

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({ success: true, searchedId: user._id });  
  } catch (err) {
    console.error('Error getting user ID:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get followers count based on user ID
app.get('/followers/:searchedId', authenticateToken, async (req, res) => {  
  const { searchedId } = req.params;

  try {
    const followers = await Following.find({ followingId: searchedId }).select("userId");  


    if (!followers || followers.length === 0) {  
      return res.status(404).json({ success: false, message: "No followers found" });
    }

    res.status(200).json({ success: true, followersCount: followers.length });  //here i need to pass all data like who follow me 
    //so that i can make an api call to the user
  } catch (e) {
    console.error("Server Error:", e);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.post('/profile/edit', authenticateToken, upload.single('dp'), async (req, res) => {
  const { name, bio, details } = req.body;
  let dp = req.file ? req.file.path : null; // Check if a file was uploaded and get the file path

  try {

    const userdata = await User.findByIdAndUpdate(req.user.id, {
      name,
      bio,
      details,
      dp  // Update dp with the new file path if available
    }, { new: true });

    if (!userdata) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.status(200).json({ success: true, message: "Profile updated successfully", user: userdata });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

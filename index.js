const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();
const app = express();
const cookieParser = require("cookie-parser");
// mongoDB
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.efrqq6z.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Let's create a cookie options for both production and local server
const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
};
//localhost:5000 and localhost:5173 are treated as same site.  so sameSite value must be strict in development server.  in production sameSite will be none
// in development server secure will false .  in production secure will be true

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://bb-money-sadatriyad.surge.sh",
      "https://bb-money.netlify.app",
      "https://binarybeasts-auth.web.app",
    ],
    credentials: true,
  })
);

async function run() {
  try {
    // await client.connect();

    // Database Collections
    const db = client.db("BB-MoneyDB");
    const UsersCollection = db.collection("users");
    const AgentsCollection = db.collection("agents");
    const AdminsCollection = db.collection("admins");

    // verifyToken
    const verifyToken = (req, res, next) => {
      //     const authHeader = req.headers.authorization;
      //     const token = authHeader && authHeader.split(" ")[1];
      //     if (!token) {
      //         return res.status(401).send({ error: "Unauthorized" });
      //     }
      //     jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      //         if (err) {
      //             console.log(err);
      //             return res.status(401).send({ error: "Unauthorized" });
      //         }
      //         req.user = decoded;
      //         req.userId = decoded.id;
      //         req.userRole = decoded.role;
      //         console.log("value in the token", decoded);
      //         next();
      //     });
      // };
      const token = req.cookies?.token;
      console.log("value inside verifyToken", token);
      if (!token) {
        return res.status(401).send({ error: "Unauthorized" });
      }
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
          console.log(err);
          return res.status(401).send({ error: "Unauthorized" });
        }
        req.user = decoded;
        req.userId = decoded.id;
        req.userRole = decoded.role;
        console.log("value in the token", decoded);
        next();
      });
    };

    //   // use verify admin after verifyToken
    //   const verifyAdmin = async (req, res, next) => {
    //     const email = req.user.email;
    //     try {
    //       const query = { email: email };
    //       const user = await UsersCollection.findOne(query);
    //       if (!user || user.role !== "admin") {
    //         return res.status(403).json({ error: "Forbidden Access" });
    //       }
    //       next(); // Proceed to the next middleware or route handler
    //     } catch (error) {
    //       console.error("Error verifying admin status:", error);
    //       res.status(500).json({ error: "Internal Server Error" });
    //     }
    //   };

    const verifyAdmin = (req, res, next) => {
      if (req.userRole !== "admin")
        return res.status(403).json({ message: "Require Admin Role" });
      next();
    };

    const verifyAgent = (req, res, next) => {
      if (req.userRole !== "agent")
        return res.status(403).json({ message: "Require Agent Role" });
      next();
    };

    app.get("/me", async (req, res) => {
      const token = req.headers.authorization?.split(" ")[1];
      // console.log("value inside me", token);
      if (!token) {
        return res
          .status(401)
          .json({ error: "Unauthorized", message: "No token provided" });
      }

      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // console.log("decoded", decoded);
        const user = await UsersCollection.findOne({
          _id: new ObjectId(decoded.userId),
        });

        if (!user) {
          return res.status(404).json({
            error: "User not found",
            message: "User associated with token not found",
          });
        }

        res.status(200).json({ user });
      } catch (error) {
        console.error("Failed to verify token:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });

    // Register Route
    app.post("/register", async (req, res) => {
      const { name, pin, mobileNumber, email, role, photoURL } = req.body;
      //   console.log(req.body);
      if (!name || !pin || !mobileNumber || !email || !role || !photoURL) {
        return res.status(400).json({ error: "All fields are required" });
      }

      try {
        const existingUser = await UsersCollection.findOne({
          $or: [{ email }, { mobileNumber }],
        });

        // console.log(existingUser);
        if (existingUser) {
          return res
            .status(400)
            .json({ error: "Email or Number already exists" });
        }

        const hashedPin = await bcrypt.hash(pin, 10);
        // console.log(`Hashed PIN during registration: ${hashedPin}`); // Debug statement
        const newUser = {
          name,
          photoURL,
          pin: hashedPin,
          mobileNumber,
          email,
          role,
          status: "pending",
          balance: role === "user" ? 40 : role === "agent" ? 10000 : 0,
          transactions: [],
          idCreatedTime: new Date(),
        };

        // Insert the user into the appropriate collection based on role
        if (role === "admin") {
          await AdminsCollection.insertOne(newUser);
        } else if (role === "agent") {
          await AgentsCollection.insertOne(newUser);
        } else {
          await UsersCollection.insertOne(newUser);
        }

        const token = jwt.sign(
          { userId: newUser._id, email: newUser.email, role: newUser.role },
          process.env.JWT_SECRET,
          {
            expiresIn: "1d",
          }
        );

        let message;
        if (role === "admin") {
          message = "Admin registration successful";
        } else if (role === "agent") {
          message = "Agent registration successful";
        } else {
          message = "User registration successful";
        }

        res.status(201).json({ token, message });
      } catch (error) {
        res.status(500).json({ error: "Server error" });
      }
    });

    // Login Route
    app.post("/login", async (req, res) => {
      const { identifier, pin } = req.body;
      //   console.log(req.body);

      try {
        // Check if user exists with email or mobile number
        const user = await UsersCollection.findOne({
          $or: [{ email: identifier }, { mobileNumber: identifier }],
        });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // // Print plain and hashed PINs for debugging
        // console.log(`Plain PIN during login: ${pin}`);
        // console.log(`Hashed PIN in DB: ${user.pin}`);

        // Verify PIN
        const isMatch = await bcrypt.compare(pin, user.pin); // Compare plain pin with hashed pin

        // console.log(`PIN match result: ${isMatch}`); // Debug statement
        if (!isMatch) {
          return res.status(401).json({ error: "Invalid PIN" });
        }
        // Generate JWT token
        const token = jwt.sign(
          { userId: user?._id, email: user?.email, role: user?.role },
          process.env.JWT_SECRET,
          {
            expiresIn: "1d",
          }
        );
        res.status(200).json({ token, message: "Login successful", user });
      } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Server error" });
      }
    });


    //creating Token
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      // console.log("user for token", user);
      const token = jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });
      res.cookie("token", token, cookieOptions).send({ token });
    });

    //clearing Token
    app.post("/logout", async (req, res) => {
      const user = req.body;
      console.log("logging out", user);
      res
        .clearCookie("token", { ...cookieOptions, maxAge: 0 })
        .send({ success: true });
    });
    console.log("pinged");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// Routes
app.get("/", (req, res) => {
  res.send("BB-Money server is running");
});

// Listen for incoming requests
app.listen(process.env.PORT || 5000, () => {
  console.log(`Server running on port ${process.env.PORT || 5000}`);
});

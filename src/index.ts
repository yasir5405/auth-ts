import dotenv from "dotenv";
import path from "path";
import express from "express";
import { userRouter } from "./routes/user.route";
import { connectDB } from "./lib/mongoose";

// Define the path for .env.local file and inject env variables into code
dotenv.config({
  path: path.resolve(__dirname, "../.env.local"),
});

// Initialise the express server
const app = express();
// Express middleware to parse incoming request
app.use(express.json());
// Initialise the port
const PORT = process.env.PORT || 8000;

connectDB();

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Welcome to Auth with TS",
  });
});

app.use("/auth", userRouter);

// Server Listening at the pre-defined port
app.listen(PORT, () => {
  console.log(`The server is running on http://localhost:${PORT}`);
});

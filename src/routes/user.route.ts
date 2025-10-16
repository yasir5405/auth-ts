import { Router } from "express";

import {
  loginUser,
  signupUser,
  verifyEmail,
} from "../controllers/user.controller";
import { signupLimiter } from "../middlewares/auth.middleware";

const userRouter = Router();

// @Route to signup users
userRouter.post("/signup", signupLimiter, signupUser);

// @Route to verify user's email
userRouter.get("/verify", verifyEmail);

// @Route to login user and return jwt token to the client
userRouter.post("/signin", loginUser);

export { userRouter };

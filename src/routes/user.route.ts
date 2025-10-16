import { Router } from "express";

import {
  loginUser,
  resetPassword,
  sendResetPasswordLink,
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

// @Route to request a password reset link to the registered email
userRouter.post("/request-password-reset-link", sendResetPasswordLink);

// @Route to verify token and update the password of the account
userRouter.post("/reset-password", resetPassword);

export { userRouter };

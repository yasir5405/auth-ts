import { Router } from "express";

import {
  fetchUser,
  loginUser,
  resendVerificationEmail,
  resetPassword,
  sendResetPasswordLink,
  signupUser,
  verifyEmail,
} from "../controllers/user.controller";
import {
  loginLimiter,
  resendVerificationEmailLimiter,
  signupLimiter,
  verifyJWT,
} from "../middlewares/auth.middleware";

const userRouter = Router();

// @Route to signup users
userRouter.post("/signup", signupLimiter, signupUser);

// @Route to verify user's email
userRouter.get("/verify", verifyEmail);

// @Route to login user and return jwt token to the client
userRouter.post("/signin", loginLimiter, loginUser);

// @Route to request a password reset link to the registered email
userRouter.post("/request-password-reset-link", sendResetPasswordLink);

// @Route to verify token and update the password of the account
userRouter.post("/reset-password", resetPassword);

// @Route to request resend of a new verification email incase the old one expired or was missed by the user or due to some backend error wasn't sent to the user
userRouter.post(
  "/resend-verification-email",
  resendVerificationEmailLimiter,
  resendVerificationEmail
);

// @Route to authenticate user using JWTs
userRouter.get("/me", verifyJWT, fetchUser);

export { userRouter };

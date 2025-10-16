import { Router } from "express";

import { signupUser, verifyEmail } from "../controllers/user.controller";
import { signupLimiter } from "../middlewares/auth.middleware";

const userRouter = Router();

// @Route to signup users
userRouter.post("/signup", signupLimiter, signupUser);

// @Route to verify user's email
userRouter.get("/verify", verifyEmail);

export { userRouter };

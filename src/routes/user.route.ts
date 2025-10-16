import { Router } from "express";

import { signupUser, verifyEmail } from "../controllers/user.controller";

const userRouter = Router();

// @Route to signup users
userRouter.post("/signup", signupUser);

// @Route to verify user's email
userRouter.get("/verify", verifyEmail);

export { userRouter };

import { Router } from "express";

import { signupUser } from "../controllers/user.controller";

const userRouter = Router();

userRouter.post("/signup", signupUser);
// TODO: Add password and confirm Password for signing up route
export { userRouter };

import { NextFunction, Request, Response } from "express";
import rateLimit from "express-rate-limit";
import jsonwebtoken, { JwtPayload } from "jsonwebtoken";
import { IUserDoc, UserModel } from "../models/user.model";

const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  // TODO: Decrease limit window to 5 when pushing to prod
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many signup attempts. Please try again in 15 minutes.",
  },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  // TODO: Decrease limit window to 5 when pushing to prod
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many login attempts. Please try again in 15 minutes.",
  },
});

const resendVerificationEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many resend email requests. Please try again in 15 minutes.",
  },
});

const verifyJWT = async (req: Request, res: Response, next: NextFunction) => {
  const tokenHeader = req.headers.authorization;
  if (!tokenHeader || !tokenHeader?.startsWith("Bearer"))
    return res.status(403).json({
      success: false,
      message: "Unauthorized or invalid token.",
    });

  const token = tokenHeader.split(" ")[1];

  if (!token)
    return res.status(403).json({
      success: false,
      message: "Unauthorized or invalid token.",
    });

  try {
    const decoded = jsonwebtoken.verify(
      token,
      process.env.JWT_SECRET! || "helloiamyasirfromranchi"
    ) as JwtPayload;

    const userId = decoded.id;

    const user: IUserDoc | null = await UserModel.findById(userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid or missing token.",
      });
    }

    const { password: _, ...safeUser } = user.toObject();

    req.user = safeUser;

    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      message:
        error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

export {
  signupLimiter,
  loginLimiter,
  resendVerificationEmailLimiter,
  verifyJWT,
};

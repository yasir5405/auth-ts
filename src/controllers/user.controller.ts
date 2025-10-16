import { Request, Response } from "express";
import { signupSchema } from "../lib/validations";
import bcrypt from "bcrypt";
import { IUserDoc, UserModel } from "../models/user.model";
import crypto from "crypto";
import {
  ITokenVerificationDoc,
  TokenVerificationModel,
} from "../models/token-verification.model";
import { sendEmail } from "../lib/email";

export const signupUser = async (req: Request, res: Response) => {
  const parsedBody = signupSchema.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Invalid data format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { email, name, password, username, image, type, confirmPassword } =
    parsedBody.data;

  try {
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and confirm password do not match.",
      });
    }

    const hashedPassword = await bcrypt.hash(password?.trim()!, 10);

    if (!hashedPassword) {
      throw new Error("Error while hashing password");
    }

    const existingUserByEmail = await UserModel.findOne({ email });
    const existingUserByUsername = await UserModel.findOne({ username });

    if (existingUserByEmail) {
      return res.status(400).json({
        success: false,
        message: "Email already taken.",
      });
    }

    if (existingUserByUsername) {
      return res.status(400).json({
        success: false,
        message: "Username already taken.",
      });
    }

    const newUser = await UserModel.create({
      email,
      username,
      name,
      password: hashedPassword,
      image,
      type,
    });

    if (!newUser) {
      return res.status(500).json({
        success: false,
        message: "Error while signing up. Please try again.",
      });
    }

    const { password: _, ...safeUser } = newUser._doc;

    res.status(201).json({
      success: true,
      message:
        "Signup successfull. A verification mail has been sent to your email.",
      data: {
        safeUser,
      },
    });

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await TokenVerificationModel.create({
      token,
      userId: safeUser._id,
      expiresAt,
    });

    await sendEmail(safeUser.email, token);
  } catch (error) {
    if (error instanceof Error) {
      if (error.message === "Error while hashing password") {
        return res.status(500).json({
          success: false,
          message: error?.message || "Internal server error.",
        });
      }
    } else {
      return res.status(500).json({
        success: false,
        message: "Internal server error.",
      });
    }
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.query;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "No token found. Unauthorized",
    });
  }

  try {
    const storedToken: ITokenVerificationDoc | null =
      await TokenVerificationModel.findOne({ token });

    if (!storedToken) {
      return res.status(401).json({
        success: false,
        message: "Token invalid or expired.",
      });
    }

    const user: IUserDoc | null = await UserModel.findById(storedToken.userId);

    if (!user) {
      return res.status(403).json({
        success: false,
        message: "No connected User found.",
      });
    }

    if (user.isVerified) {
      return res.status(400).json({
        success: false,
        message: "Your email is already verified.",
      });
    }

    user.isVerified = true;

    await user.save();

    await TokenVerificationModel.findByIdAndDelete(storedToken._id);

    res.status(200).json({
      success: true,
      message: "Your email has been verified successfully.",
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

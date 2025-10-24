import { Request, Response } from "express";
import {
  loginSchema,
  resendVerificationEmailSchema,
  signupSchema,
} from "../lib/validations";
import bcrypt from "bcrypt";
import { IUserDoc, UserModel } from "../models/user.model";
import crypto from "crypto";
import {
  ITokenVerificationDoc,
  TokenVerificationModel,
} from "../models/token-verification.model";
import { sendEmail, sendPasswordResetEmail } from "../lib/email";
import jsonwebtoken, { JwtPayload } from "jsonwebtoken";
import {
  IPasswordResetTokenDoc,
  passwordResetTokenModel,
} from "../models/password-reset-token.model";

//Controller to register user
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
      return res.status(409).json({
        success: false,
        message: "Account already exists with this email.",
      });
    }

    if (existingUserByUsername) {
      return res.status(409).json({
        success: false,
        message: "Account already exists with this username.",
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
        error:
          error instanceof Error ? error.message : "Internal server error.",
      });
    }
  }
};

//Controller to verify user's email
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
      return res.status(409).json({
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
    return res.status(500).json({
      success: false,
      message: "Internal server error.",
      error: error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

//Controller to login user
export const loginUser = async (req: Request, res: Response) => {
  const parsedBody = loginSchema.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Invalid data format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { email, username, password, type } = parsedBody.data;

  try {
    const query = type === "email" ? { email } : { username };
    const user: IUserDoc | null = await UserModel.findOne(query);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (!user.password) {
      return res.status(400).json({
        success: false,
        message:
          "This account is not associated with credentials. Use your other login methods you used earlier.",
      });
    }

    if (!user.isVerified) {
      return res.status(401).json({
        success: false,
        message: "Please verify your email before logging in.",
      });
    }

    const isMatch = await bcrypt.compare(password!, user.password);

    if (!isMatch) {
      return res.status(404).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const token = jsonwebtoken.sign(
      {
        id: user._id,
      },
      process.env.JWT_SECRET!
    );

    if (!token) {
      return res.status(500).json({
        success: false,
        message: "Error in signing in. Please try again.",
      });
    }

    const { password: _, ...safeUser } = user.toObject();

    res.status(200).json({
      success: true,
      data: {
        user: safeUser,
        token: token,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

//Controller to send password reset link
export const sendResetPasswordLink = async (req: Request, res: Response) => {
  const parsedBody = signupSchema.partial().safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(401).json({
      success: false,
      message: "Invalid data format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { email } = parsedBody.data;

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Please provide an email to recieve password reset link.",
    });
  }

  try {
    const user: IUserDoc | null = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found with this email: " + email,
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await passwordResetTokenModel.deleteMany({ userId: user._id });

    await passwordResetTokenModel.create({
      token,
      userId: user._id,
      expiresAt,
    });

    res.status(201).json({
      success: true,
      message: "Password reset link sent to your registered email.",
    });

    await sendPasswordResetEmail(email, token);
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

//Controller to reset password
export const resetPassword = async (req: Request, res: Response) => {
  const { token } = req.query;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Missing or Invalid token.",
    });
  }

  const partialSchema = signupSchema.partial();

  const parsedBody = partialSchema.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Invalid data format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { password } = parsedBody.data;

  if (!password || password.length === 0 || password === "") {
    return res.status(400).json({
      success: false,
      message: "New Password is required to reset your current password.",
    });
  }

  try {
    const storedToken: IPasswordResetTokenDoc | null =
      await passwordResetTokenModel.findOne({ token });

    if (!storedToken) {
      return res.status(401).json({
        success: false,
        message: "Invalid token. Unauthorized.",
      });
    }

    const user: IUserDoc | null = await UserModel.findById(storedToken.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid token. Unauthorized.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser: IUserDoc | null = await UserModel.findByIdAndUpdate(
      user._id,
      {
        password: hashedPassword,
      },
      { new: true }
    );

    if (!newUser) {
      return res.status(500).json({
        success: false,
        message: "Error while updating password. Please try again.",
      });
    }

    const { password: _, ...safeUser } = newUser.toObject();

    await passwordResetTokenModel.findByIdAndDelete(storedToken._id);

    res.status(201).json({
      success: true,
      message: "Password reset successfull.",
      data: {
        user: safeUser,
      },
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

//Controller to resend verification email
export const resendVerificationEmail = async (req: Request, res: Response) => {
  const parsedBody = resendVerificationEmailSchema.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Invalid input format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { email } = parsedBody.data;

  try {
    const user: IUserDoc | null = await UserModel.findOne({ email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No account found with this email address.",
      });
    }

    if (user.isVerified) {
      return res.status(409).json({
        success: false,
        message: "Your account is already verified.",
      });
    }

    await TokenVerificationModel.deleteMany({ userId: user._id });

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await TokenVerificationModel.create({
      token,
      userId: user._id,
      expiresAt,
    });

    res.status(200).json({
      success: true,
      message: "A new verification email has been sent to your inbox.",
    });

    await sendEmail(email, token);
  } catch (error) {
    res.status(500).json({
      success: false,
      message:
        error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

//Controller to authenticate user using JWTs
export const fetchUser = async (req: Request, res: Response) => {
  const user = req.user;
  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Invalid or missing token.",
    });
  }
  try {
    res.status(200).json({
      success: true,
      message: "User details fetched successfully",
      user: user,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message:
        error instanceof Error ? error.message : "Internal server error.",
    });
  }
};

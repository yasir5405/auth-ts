import { Request, Response } from "express";
import { signupSchema } from "../lib/validations";
import bcrypt from "bcrypt";
import { UserModel } from "../models/user.model";

export const signupUser = async (req: Request, res: Response) => {
  const parsedBody = signupSchema.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Invalid data format.",
      error: parsedBody.error.issues.map((issue) => issue.message),
    });
  }

  const { email, name, password, username, image, type } = parsedBody.data;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

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

    res.status(201).json({
      success: true,
      message: "Signup successfull.",
      data: {
        newUser,
      },
    });
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

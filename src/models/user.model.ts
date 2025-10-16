import mongoose, { Document, models } from "mongoose";

import { Schema } from "mongoose";

export interface IUser {
  name: string;
  username: string;
  email: string;
  image?: string;
  password?: string;
  type: "admin" | "user";
  isVerified?: boolean;
}

export interface IUserDoc extends IUser, Document {}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    image: {
      type: String,
      default: null,
    },
    password: {
      type: String,
    },
    type: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

const UserModel = models?.User || mongoose.model<IUser>("User", userSchema);

export { UserModel };

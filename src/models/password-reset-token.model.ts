import mongoose, { ObjectId, Document, model, models } from "mongoose";

export interface IPasswordResetTokenSchema {
  token: string;
  userId: ObjectId;
  expiresAt: Date;
}

export interface IPasswordResetTokenDoc
  extends IPasswordResetTokenSchema,
    Document {}

const passwordResetTokenSchema = new mongoose.Schema<IPasswordResetTokenSchema>(
  {
    token: {
      type: String,
      required: true,
    },
    userId: {
      type: mongoose.Types.ObjectId,
      ref: "users",
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
  },
  { timestamps: true }
);

const passwordResetTokenModel =
  models?.PasswordResetToken ||
  model<IPasswordResetTokenSchema>(
    "PasswordResetToken",
    passwordResetTokenSchema
  );

export { passwordResetTokenModel };

import mongoose, { ObjectId, models, model, Document } from "mongoose";

interface ITokenVerification {
  token: string;
  userId: ObjectId;
  expiresAt: Date;
}

export interface ITokenVerificationDoc extends ITokenVerification, Document {}

const TokenVerificationSchema = new mongoose.Schema<ITokenVerification>(
  {
    token: {
      type: String,
      required: true,
    },
    userId: {
      type: mongoose.Types.ObjectId,
      required: true,
      ref: "users",
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  { timestamps: true }
);

const TokenVerificationModel =
  models?.TokenVerification ||
  model("VerificationToken", TokenVerificationSchema);

export { TokenVerificationModel };

import nodemailer from "nodemailer";

export const sendEmail = async (email: string, token: string) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  const link = `${
    process.env.FRONTEND_URL || `http://localhost:${process.env.PORT}`
  }/auth/verify?token=${token}`;

  const info = await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Email verification email from Auth",
    text: "Please click on the below link to verify your email your email in order to sign in with your Auth account.",
    html: `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 10px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(90deg,#4f46e5,#06b6d4);color:#fff;padding:16px 20px;text-align:center;font-weight:600;font-size:18px;">
      Verify Your Email
    </div>
    <div style="padding:24px;text-align:center;color:#333;">
      <p style="font-size:15px;margin-bottom:20px;">
        Thanks for signing up! Click the button below to verify your email address.
      </p>
      <a href="${link}" style="display:inline-block;padding:12px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
        Verify Email
      </a>
      <p style="font-size:13px;color:#666;margin-top:20px;">
        If the button doesn’t work, copy this link:<br>
        <a href="${link}" style="color:#4f46e5;word-break:break-all;">${link}</a>
      </p>
    </div>
    <div style="background:#f9fafb;color:#777;font-size:12px;text-align:center;padding:12px;">
      If you didn’t create an account, ignore this email.<br>
      © ${new Date().getFullYear()} Auth
    </div>
  </div>`,
  });

  return info;
};

export const sendPasswordResetEmail = async (email: string, token: string) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const link = `${
    process.env.FRONTEND_URL || `http://localhost:${process.env.PORT}`
  }/auth/reset-password?token=${token}`;

  const info = await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password reset for your Auth account",
    text: "Please click on the below link to reset your password in order to sign in with your Auth account.",
    html: `
  <div style="font-family:Arial,Helvetica,sans-serif;max-width:600px;margin:auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 4px 10px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(90deg,#4f46e5,#06b6d4);color:#fff;padding:16px 20px;text-align:center;font-weight:600;font-size:18px;">
      Reset Your Password
    </div>
    <div style="padding:24px;text-align:center;color:#333;">
      <p style="font-size:15px;margin-bottom:20px;">
        Click the button below to reset your password.
      </p>
      <a href="${link}" style="display:inline-block;padding:12px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:8px;font-weight:600;">
        Reset Password
      </a>
      <p style="font-size:13px;color:#666;margin-top:20px;">
        If the button doesn’t work, copy this link:<br>
        <a href="${link}" style="color:#4f46e5;word-break:break-all;">${link}</a>
      </p>
    </div>
    <div style="background:#f9fafb;color:#777;font-size:12px;text-align:center;padding:12px;">
      If you didn’t request password request, ignore this email.<br>
      © ${new Date().getFullYear()} Auth
    </div>
  </div>`,
  });

  return info;
};

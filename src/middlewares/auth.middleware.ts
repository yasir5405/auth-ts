import rateLimit from "express-rate-limit";

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

export { signupLimiter };

import { z } from "zod";

const signupSchema = z.object({
  name: z
    .string({ error: "Name is required." })
    .min(2, { error: "Name should be at least 2 characters." })
    .max(100, { error: "Name cannot be more than 100 characters." }),
  username: z
    .string({ error: "Username is required." })
    .min(2, { error: "Username should be at least 2 characters." })
    .max(100, { error: "Username cannot be more than 100 characters long." }),
  email: z.email({
    error: "Email is required. Please enter a valid email address.",
  }),
  image: z.string().optional(),
  password: z
    .string()
    .min(8, { error: "Password should be at least 8 characters." })
    .max(100, { error: "Password cannot be more than 100 characters." })
    .regex(/[A-Z]/, {
      message: "Password must contain at least one uppercase letter.",
    })
    .regex(/[a-z]/, {
      message: "Password must contain at least one lowercase letter.",
    })
    .regex(/[0-9]/, { message: "Password must contain at least one number." })
    .regex(/[^a-zA-Z0-9]/, {
      message: "Password must contain at least one special character.",
    })
    .optional(),
  confirmPassword: z
    .string()
    .min(8, { error: "Confirm password should be at least 8 characters." })
    .max(100, {
      error: "Confirm password cannot be more than 100 characters.",
    })
    .optional(),
  type: z.enum(["admin", "user"]).default("user").optional(),
});

export { signupSchema };

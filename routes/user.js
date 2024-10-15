const { Router } = require("express");
const { userModel, courseModel, purchaseModel } = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { JWT_USER } = require("../config");
const { userMiddleware } = require("../middleware/user");
const { z } = require("zod");
const userRouter = Router();

// Define Zod schemas for validation
const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8), // Ensure password is at least 8 characters
  firstName: z.string().min(1), // Require first name
  lastName: z.string().min(1), // Require last name
});

const signinSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1), // Password is required for signin
});

userRouter.post("/signup", async function (req, res) {
  const { email, password, firstName, lastName } = req.body;

  try {
    signupSchema.parse({ email, password, firstName, lastName });
    const hashedPassword = await bcrypt.hash(password, 5);

    await userModel.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
    });
    res.json({
      message: "Signup done",
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors,
      });
    } else {
      console.error(error);
      res.status(500).json({
        message: "Signup failed",
      });
    }
  }
});
userRouter.post("/signin", async function (req, res) {
  const { email, password } = req.body;
  try {
    signinSchema.parse({ email, password });
    const user = await userModel.findOne({
      email,
    });

    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        {
          id: user._id.toString(),
        },
        JWT_USER
      );
      res.json({
        token,
      });
    } else {
      res.status(403).json({
        message: "Incorrect credentials",
      });
    }
  } catch (error) {
    // Check if error is from Zod validation or database operation
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        message: "Validation error",
        errors: error.errors,
      });
    } else {
      console.error(error);
      res.status(500).json({
        message: "Sign-in failed",
      });
    }
  }
});

userRouter.get("/purchases", userMiddleware, async function (req, res) {
  try {
    const userId = req.userId;
    const purchases = await purchaseModel.find({
      userId,
    });
    const purchasedCourseId = purchases.map((purchase) => purchase.courseId);

    const coursesData = await courseModel.find({
      id: { $in: purchasedCourseId },
    });
    res.json({
      purchases,
      coursesData,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to retrieve purchases" });
  }
});

module.exports = {
  userRouter,
};

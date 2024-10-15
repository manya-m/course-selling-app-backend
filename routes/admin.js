const { Router } = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");
const { adminModel, courseModel } = require("../db");
const { JWT_ADMIN } = require("../config");
const { adminMiddleware } = require("../middleware/admin");

const adminRouter = Router();
const SALT_ROUNDS = 5;

// Define Zod schemas for validation
const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  firstName: z.string().min(1),
  lastName: z.string().min(1),
});

const signinSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

adminRouter.post("/signup", async function (req, res) {
  const { email, password, firstName, lastName } = req.body;

  try {
    // Validate the request body
    signupSchema.parse({ email, password, firstName, lastName });

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    await adminModel.create({
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

adminRouter.post("/signin", async function (req, res) {
  const { email, password } = req.body;

  try {
    // Validate the request body
    signinSchema.parse({ email, password });

    const admin = await adminModel.findOne({ email });

    if (admin && (await bcrypt.compare(password, admin.password))) {
      const token = jwt.sign({ id: admin._id.toString() }, JWT_ADMIN);

      res.json({
        token,
      });
    } else {
      res.status(403).json({
        message: "Incorrect credentials",
      });
    }
  } catch (error) {
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

adminRouter.post("/course", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const { title, description, imageUrl, price } = req.body;

  // creating a web3 saas in 6 hours
  const course = await courseModel.create({
    title: title,
    description: description,
    imageUrl: imageUrl,
    price: price,
    creatorId: adminId,
  });

  res.json({
    message: "Course created",
    courseId: course._id,
  });
});

adminRouter.put("/course", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const { title, description, imageUrl, price, courseId } = req.body;

  const course = await courseModel.updateOne(
    {
      _id: courseId,
      creatorId: adminId,
    },
    {
      title: title,
      description: description,
      imageUrl: imageUrl,
      price: price,
    }
  );

  res.json({
    message: "Course updated",
    courseId: course._id,
  });
});
adminRouter.get("/course/bulk", adminMiddleware, async function (req, res) {
  const adminId = req.userId;

  const courses = await courseModel.find({
    creatorId: adminId,
  });

  res.json({
    courses,
  });
});

module.exports = {
  adminRouter,
};

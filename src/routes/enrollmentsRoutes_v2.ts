import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();
import { zStudentId, zCourseId } from "../libs/zodValidators.js";
import type { User, UserPayload, CustomRequest, Student, Course, Enrollment } from "../libs/types.ts";

// import database
import { enrollments, students, courses } from "../db/db.js";
import { users, reset_users } from "../db/db.js";
import { success } from "zod";
import { count } from "node:console";
import { token } from "morgan";
import { fa } from "zod/v4/locales";

const router = Router();

// POST /api/v2/enrollments/login
router.post("/login", (req: Request, res: Response) => {
  // 1. get username and password from body
  const {username, password} = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  // 2. check if user exists (search with username & password in DB)
  //if not found
  if(!user){
    return res.status(401).json({
      success: false,
      message: "Invalid username or password"
    });
  }

  // 3. create JWT token (with user info object as payload) using JWT_SECRET_KEY
  const jwt_secrat = process.env.JWT_SECRET || "this_is _my_secret"
  const Token = jwt.sign({
    //app paylond
    username: user.username,
    studentId: user.studentId,
    role: user.role
  },
  jwt_secrat,
  { expiresIn: "30m"}
  );

  //    (optional: save the token as part of User data)

  // 4. send HTTP response with JWT token
  return res.status(200).json({
    success: true,
    message: "login sucessful",
    token: Token
  })

});

// POST /api/v2/enrollments
router.post("/", (req: Request, res: Response) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authorization header is required",
      });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token is required",
      });
    }

    const jwt_secret = process.env.JWT_SECRET || "this_is _my_secret";
    const payload = jwt.verify(token, jwt_secret) as UserPayload;

    const user = users.find((u) => u.username === payload.username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }
    if (user.role === "ADMIN") {
      return res.status(403).json({
        ok: true,
        message: "Only students can access this API route",
      });
    }
    const { courseId } = req.body;
  } catch (err) {
    return res.status(403).json({
      success: false,
      message: "Invalid or expired token",
      error: err,
    });
  }
});

// GET /api/v2/enrollments
router.get("/", (req: Request, res: Response) => {
  
  try {
    // 1. get the Authorization header from the request
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authorization header is required",
      });
    }
    // 2. extract the token from the Authorization header
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token is required",
      });
    }

    const jwt_secret = "this_is_a_secret_key_for_jwt";
    const payload = jwt.verify(token, jwt_secret) as UserPayload;

    const user = users.find((u) => u.username === payload.username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    if (user.role === "ADMIN") {
      return res.status(200).json({
        ok: true,
        enrollments: enrollments,
      });
    }

    if (user.role === "STUDENT") {
      const studentEnrollments = enrollments.filter(
        (e) => e.studentId === user.studentId
      );
      return res.status(200).json({
        success: true,
        data: studentEnrollments,
      });
    }

    return res.status(403).json({
      success: false,
      message: "Forbidden access",
    });

  } catch (err) {
    return res.status(403).json({
      success: false,
      message: "Invalid or expired token",
      error: err,
    });
  }
});

// DELETE /api/v2/enrollments
router.delete("/", (req: Request, res: Response) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authorization header is required",
      });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token is required",
      });
    }

    const jwt_secret = process.env.JWT_SECRET || "this_is _my_secret";
    const payload = jwt.verify(token, jwt_secret) as UserPayload;

    const user = users.find((u) => u.username === payload.username);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized user",
      });
    }

    if (user.role === "ADMIN") {
      return res.status(403).json({
        success: false,
        message: "Admin cannot perform this action", //  ใช้ message เดียวกับข้อ POST รูปที่ 2
      });
    }

    const { courseNo } = req.body;

    if (!courseNo) {
      return res.status(400).json({
        success: false,
        message: "courseNo is required",
      });
    }

    const index = enrollments.findIndex(
      (e) => e.studentId === user.studentId && ((e as any).courseNo === courseNo || e.courseId === courseNo)
    );

    if (index === -1) {
      return res.status(404).json({
        success: false,
        message: "Enrollment not found",
      });
    }

    enrollments.splice(index, 1);

    return res.status(200).json({
      ok: true,
      message: "You have dropped from this course. See you next semester.", 
    });

  } catch (err) {
    return res.status(403).json({
      success: false,
      message: "Invalid or expired token",
      error: err,
    });
  }
});

export default router;

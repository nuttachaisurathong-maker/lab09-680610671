import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, UserPayload, CustomRequest } from "../libs/types.ts";

// import database
import { users, reset_users } from "../db/db.js";
import { success } from "zod";
import { count } from "node:console";
import { token } from "morgan";
import { fa } from "zod/v4/locales";

const router = Router();

// POST /api/v2/users/login
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

// GET /api/v2/users
router.get("/", (req: Request, res: Response) => {
  
  const authHeader = req.headers["authorization"]
  if(!authHeader || !authHeader.startsWith("Bearer")){
    return res.status(401).json({
      success: false,
      message: "Authorization header is required"
    })
  }
  
  console.log(authHeader);
  const token = authHeader.split(" ")[1]

  if(token === null){
      return res.status(401).json({
      success: false,
      message: "Token is required"
    })
  }

  const jwt_secrat = process.env.JWT_SECRET || "this_is _my_secret";
  jwt.verify(token, jwt_secrat, (err, payload) =>{
    if(err){
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token"
      });
    }

    //find user by paylond
    const user_payload = payload as UserPayload;
    const user = users.find((u) => u.username === user_payload.username)

    if  (!user || user.role !== "ADMIN"){
        return res.status(401).json({
        success: false,
        message: "Unauthorized user"
      });
    }

  })

  try {
    // return all users
    return res.json({
      success: true,
      data: users,
    });
  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});


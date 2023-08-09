import { Router } from "express";
import { methods as userController } from "./../controllers/user.controller";
import { checkAuth } from "./../middleware/authentication";

const router = Router();

router.post("/register", userController.postRegister);
router.post("/login", userController.postLogin);
router.get("/user", checkAuth, userController.getUser);
export default router;

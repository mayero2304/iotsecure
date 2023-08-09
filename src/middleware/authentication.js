import jwt from "jsonwebtoken";

let checkAuth = (req, res, next) => {
  let token = req.cookies["access_token"];
  jwt.verify(token, "iotsecure", (error, decoded) => {
    if (error) {
      return res.status(401).json({
        status: "error",
        error: error,
      });
    }
    req.userId = decoded.id;
    next();
  });
};

module.exports = { checkAuth };

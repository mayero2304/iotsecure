import { getConnection } from "./../database/database";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

/* -------------------------------------------------------------------------- */
/*                                  REGISTER                                  */
/* -------------------------------------------------------------------------- */
const postRegister = async (req, res) => {
  try {
    const { user_name, user_email, user_password } = req.body;
    const passwordbcryt = bcrypt.hashSync(user_password, 10);

    const newUser = { user_name, user_email, user_password: passwordbcryt };
    const connection = await getConnection();
    await connection.query("INSERT INTO users SET ?", newUser);
    res.json({ message: "User created" });
  } catch (error) {
    handleServerError(res, error);
  }
};

/* -------------------------------------------------------------------------- */
/*                                    LOGIN                                   */
/* -------------------------------------------------------------------------- */
const postLogin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const connection = await getConnection();
    const query = "SELECT * FROM users WHERE user_email = ?";
    const result = await connection.query(query, [email]);
    if (
      result.length > 0 &&
      bcrypt.compareSync(password, result[0].user_password)
    ) {
      const token = jwt.sign({ id: result[0].user_id }, "iotsecure", {
        expiresIn: 60 * 60 * 24 * 30,
      });

      setAccessTokenCookie(res, token);

      return res.json(token);
    } else {
      handleInvalidCredentials(res);
    }
  } catch (error) {
    handleServerError(res, error);
  }
};

const getUser = async (req, res) => {
  try {
    const token = getDecodedToken(req);
    if (!token) {
      return handleUnauthorized(res);
    }

    const connection = await getConnection();
    const query =
      "SELECT user_id, user_name, user_email FROM users WHERE user_id = ?";
    const result = await connection.query(query, [token.id]);

    if (result.length > 0) {
      const user = result[0];
      const { user_id, user_name, user_email } = user;

      const response = {
        id: user_id,
        name: user_name,
        email: user_email,
      };
      return res.json(response);
    } else {
      return res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    handleServerError(res, error);
  }
};

/* -------------------------------------------------------------------------- */
/*                                  FUNCTIONS                                 */
/* -------------------------------------------------------------------------- */
const handleServerError = (res, error) => {
  res.status(500).json({ status: "error", error: "Internal server error" });
};

const handleInvalidCredentials = (res) => {
  const response = {
    status: "error",
    error: "Invalid Credentials",
  };
  res.status(401).json(response);
};

const handleUnauthorized = (res) => {
  return res.status(401).json({ error: "Unauthorized" });
};

const setAccessTokenCookie = (res, token) => {
  res.cookie("access_token", token, {
    expiresIn: 60 * 60 * 24 * 30,
    secure: false,
    httpOnly: true,
  });
};

const getDecodedToken = (req) => {
  const cookie = req.cookies["access_token"];
  if (cookie) {
    try {
      const decodedToken = jwt.verify(cookie, "iotsecure");
      return decodedToken;
    } catch (error) {
      return null;
    }
  }
  return null;
};

export const methods = {
  postRegister,
  postLogin,
  getUser,
};

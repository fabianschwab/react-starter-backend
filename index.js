require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const users = [
  {
    id: 1001,
    username: "admin",
    password: "password",
  },
];

let refreshTokens = [];
let invalidAccessToken = [];

/**
 * Generates an access token for a given user and signs ID and username
 */
const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRATION_TIME }
  );
};

/**
 * Generates a refresh token for a given user and signs ID and username.
 * This token can be used to get a new access token without login in again.
 * All generated refresh token will be saved, till they are expired or removed when a user logs out.
 */
const generateRefreshToken = (user) => {
  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME }
  );

  // Saving refresh token, to invalidate them when user logs out.
  refreshTokens.push({ userId: user.id, refreshToken: token });
  return token;
};

/**
 * Invalidates access tokens:
 * It is a list with blocked access tokens, till they are expired.
 */
const invalidateAccessToken = (token) => {
  invalidAccessToken.push(token);
};

/**
 * Invalidates refresh tokens for the user how is logging out.
 *
 * TODO: Fix the issue
 *
 * ! If once logged out all refresh tokens get removed.
 *
 * ! Side effect:
 * ! Also "logged out" from different browsers and machines.
 * ! Can't refresh access token.
 *
 * ? Solution cloud be:
 * ? Logout is an endpoint which needs httpOnly cookie and invalidates this exact refresh token.
 * ? Logouts for all Tabs cloud be realized on client side with global `localStorage` listener:
 * ? When state `logout` is set, than trigger logout function.
 */
const invalidateRefreshTokensOfUser = (user) => {
  refreshTokens = refreshTokens.filter((entry) => entry.userId !== user.id);
};

/**
 * Return full user details to given ID
 * TODO: export to user util class later on when stored in DB
 */
const getUser = (id) => {
  return users.find((user) => user.id === id);
};

/**
 * Verify JWT middleware:
 * If access token is valid and not blocked because of a logout.
 */
const verify = (request, response, next) => {
  const authHeader = request.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (error, signedUserPayload) => {
      if (error || invalidAccessToken.includes(token)) {
        return response.status(403).json({ message: "Token is not valid." });
      } else {
        const user = getUser(signedUserPayload.id);
        request.user = user;
        next();
      }
    });
  } else {
    response.status(401).json({ message: "You are not authenticated." });
  }
};

/**
 * SignIn
 */
app.post("/api/signin", (request, response) => {
  const { username, password } = request.body;

  if (!username || !password) {
    return response
      .status(400)
      .json({ message: "Username or password is missing." });
  }

  const user = users.find((user) => {
    if (user.username === username && user.password === password) {
      return user;
    }
  });

  if (user) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    response.cookie("refreshToken", refreshToken, {
      httpOnly: true,
    });
    response.json({ accessToken });
  } else {
    response.status(400).json({ message: "Incorrect username or password." });
  }
});

/**
 * Logout and invalidate access and refresh token
 */
app.get("/api/logout", verify, (request, response) => {
  const authHeader = request.headers.authorization;
  const accessToken = authHeader.split(" ")[1];

  invalidateAccessToken(accessToken);
  invalidateRefreshTokensOfUser(request.user);

  response.cookie("refreshToken", "", { httpOnly: true });

  return response.status(200).send({ message: "You logout successful." });
});

/**
 * Refresh SignIn: Endpoint for new token when accessToken is expired
 */
app.post("/api/refresh", (request, response) => {
  const refreshToken = request.body.refreshToken;

  if (!refreshToken) {
    return response.status(401).json({ message: "RefreshToken is missing." });
  }
  if (!refreshTokens.includes(refreshToken)) {
    return response.status(403).json({ message: "RefreshToken is not valid." });
  } else {
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (error, user) => {
      if (error) {
        return response.status(403).json({ message: "Refresh token expired." });
      } else {
        invalidateRefreshToken(refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        response.cookie("refreshToken", newRefreshToken, { httpOnly: true });

        response
          .status(200)
          .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
      }
    });
  }
});

/**
 * ! Start listing endpoints here
 */
app.delete("/api/users/:userId", verify, (request, response) => {
  console.log(request.user);

  if (request.user.id === parseInt(request.params.userId)) {
    response.status(200).json({ message: "User has been deleted." });
  } else {
    response
      .status(403)
      .json({ message: "You are not allowed to delete this user." });
  }
});

/**
 * Start server on defined port in the .env file
 */
app.listen(process.env.SERVER_PORT, () => {
  console.log("Server ist running on port " + process.env.SERVER_PORT);
});

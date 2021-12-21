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
 * Generates a refresh token for a given user and signs ID and username
 * This token can be used to get a new access token without login in again
 */
const generateRefreshToken = (user) => {
  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRATION_TIME }
  );

  refreshTokens.push(token);

  return token;
};

/**
 * Invalidates refresh tokens
 */
const invalidateRefreshToken = (refreshToken) => {
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
};

/**
 * Return full user details to given ID
 */
const getUser = (id) => {
  return users.find((user) => user.id === id);
};

/**
 * Verify JWT middleware
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

        response
          .status(200)
          .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
      }
    });
  }
});

/**
 * Logout and invalidate all token
 */
app.post("/api/logout", verify, (request, response) => {
  const { refreshToken, accessToken } = request.body;

  if (!refreshToken || !accessToken) {
    return response
      .status(400)
      .json({ message: "RefreshToken or accessToken is missing." });
  } else {
    invalidateRefreshToken(refreshToken);
    invalidAccessToken.push(accessToken);
    return response.status(200).send({ message: "You logout successful." });
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

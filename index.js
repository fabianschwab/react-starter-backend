require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cookieParser());

const users = [
  {
    id: 1001,
    username: "admin",
    email: "admin@admin.com",
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
 *
 * * ADD issued add check to find the right token?
 */
const invalidateRefreshTokensOfUser = (user) => {
  refreshTokens = refreshTokens.filter((entry) => entry.userId !== user.id);
};

/**
 * Check if the refresh token is in the list of valid tokens
 */
const checkForExistingRefreshToken = (token) => {
  return refreshTokens.find((entry) => {
    return entry.refreshToken === token;
  });
};

/**
 * Verify JWT middleware:
 * If access token is valid and not blocked because of a logout.
 */
const verify = (request, response, next) => {
  const authHeader = request.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (error, user) => {
      if (error || invalidAccessToken.includes(token)) {
        return response.status(403).json({ message: "Token is not valid." });
      } else {
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
    // invalidateRefreshTokensOfUser(user);
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    response.json({
      accessToken,
      refreshToken,
      user: { id: user.id, username: user.username },
    });
  } else {
    response.status(400).json({ message: "Incorrect username or password." });
  }
});

/**
 * SignUp
 */
app.post("/api/signup", (request, response) => {
  const { username, email, password, confirmPassword } = request.body;

  if (!username || !email || !password || !confirmPassword) {
    return response
      .status(400)
      .json({ message: "Not all required fields are present." });
  }
  const checkIfRegisteredUser = users.find((user) => {
    if (user.email === email) {
      return user;
    }
  });
  if (checkIfRegisteredUser) {
    return response
      .status(409)
      .json({ message: "User with this email address already registered." });
  }

  const checkIfUsernameTaken = users.find((user) => {
    if (user.username === username) {
      return user;
    }
  });
  if (checkIfUsernameTaken) {
    return response.status(409).json({ message: "Username already taken." });
  }

  users.push({ id: users.length + 1001, username, email, password });

  return response.status(201).send();
});

/**
 * Logout: Invalidate access and refresh token
 */
app.get("/api/signout", verify, (request, response) => {
  const authHeader = request.headers.authorization;
  const accessToken = authHeader.split(" ")[1];

  invalidateAccessToken(accessToken);
  invalidateRefreshTokensOfUser(request.user);

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
  if (!checkForExistingRefreshToken(refreshToken)) {
    return response.status(403).json({ message: "RefreshToken is not valid." });
  } else {
    jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (error, user) => {
      if (error) {
        return response.status(403).json({ message: "Refresh token expired." });
      } else {
        invalidateRefreshTokensOfUser(user);
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        response.status(200).json({
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
          username: user.username,
        });
      }
    });
  }
});

/**
 * ! Start listing endpoints here
 */
app.get("/api/profile", verify, (request, response) => {
  const foundUser = users.find((user) => {
    return user.id === request.user.id;
  });
  if (foundUser) {
    return response.status(200).json(foundUser);
  } else {
    return response.status(500).json({ message: "Something went wrong." });
  }
});

app.get("/api/users/:userId", verify, (request, response) => {
  const foundUser = users.find((user) => {
    return user.id === parseInt(request.params.userId);
  });
  console.log(parseInt(request.params.userId));
  if (foundUser) {
    return response.status(200).json(foundUser);
  } else {
    return response.status(404).json({ message: "User not found." });
  }
});

/**
 * Start server on defined port in the .env file
 */
app.listen(process.env.SERVER_PORT, () => {
  console.log("Server ist running on port " + process.env.SERVER_PORT);
});

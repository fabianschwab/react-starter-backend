const { response } = require("express");
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

app.post("/api/signin", (request, response) => {
  const { username, password } = request.body;

  const user = users.find((user) => {
    if (user.username === username && user.password === password) {
      return user;
    }
  });
  if (user) {
    const accessToken = jwt.sign(
      { id: user.id, username: user.username },
      "token"
    );
    response.json({ username: user.username, accessToken });
  } else {
    response.status(400).json({ message: "Incorrect username or password." });
  }
});

app.listen(5000, () => {
  console.log("Server ist running on port 5000.");
});

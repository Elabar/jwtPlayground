const fastify = require("fastify");
const jwt = require("jsonwebtoken");
const Boom = require("@hapi/boom");
const _ = require("lodash");
const { users } = require("./user");
const server = fastify({ logger: true });
const access_secret = "secret123";
const refresh_secret = "refresh123";

server.register(require("fastify-cors"), {
  origin: '*'
});

server.post("/login", (req, res) => {
  try {
    let { username, password } = req.body;
    let user = _.find(users, (o) => {
      return o.username === username;
    });
    let token;
    let refreshToken;
    if (user.password === password) {
      // generate token here
      token = jwt.sign({ user: user, type: "access_token" }, access_secret, {
        expiresIn: "1m",
      });
      let uniqueRefreshSecret = refresh_secret + user.password;
      refreshToken = jwt.sign(
        { type: "refresh_token", userId: user.id },
        uniqueRefreshSecret,
        { expiresIn: "1h" }
      );
    } else {
      throw new Error("Invalid password");
    }
    return { token, refreshToken };
  } catch (err) {
    throw new Boom.boomify(err);
  }
});

server.post("/verifyToken", (req, res) => {
  try {
    let { authentication } = req.headers;
    if(!authentication){
        throw new Error("Invalid token")
    }
    let payload = jwt.decode(authentication);
    if (!payload || payload.type === "refresh_token") {
      throw new Error("Invalid token");
    }
    jwt.verify(authentication, access_secret);
    return true;
  } catch (err) {
    throw new Boom.boomify(err);
  }
});

server.post("/refreshToken", (req, res) => {
  try {
    let { refreshToken } = req.body;
    let payload = jwt.decode(refreshToken);
    console.log(payload);
    if (payload.type === "access_token") {
      throw new Error("Invalid token");
    }
    let user = _.find(users, (o) => {
      return o.id === payload.userId;
    });
    jwt.verify(refreshToken, refresh_secret + user.password);
    let token = jwt.sign({ user: user, type: "access_token" }, access_secret, {
      expiresIn: "1m",
    });
    let newRefreshToken = jwt.sign(
      { type: "refresh_token", userId: user.id },
      refresh_secret + user.password,
      { expiresIn: "1h" }
    );
    return { token, newRefreshToken };
  } catch (err) {
    throw new Boom.boomify(err);
  }
});

server.listen(4750, (err, addr) => {
  server.log.info(`server started listening on port ${addr}`);
});

import express from "express";
import bodyParser from "body-parser";
import pg from "pg";

const app = express();
const port = 3000;

let totalCorrect = 0;
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "web",
  password: "Gpr@1976",
  port: 5432,
});
db.connect();


// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});

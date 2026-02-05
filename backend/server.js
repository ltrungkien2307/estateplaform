require("dotenv").config();
const app = require('./app');
const PORT = process.env.PORT || 5000;
const connectDB = require("./config/db");

connectDB();
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

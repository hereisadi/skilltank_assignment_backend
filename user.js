const mongoose = require("mongoose");

const Authschema = new mongoose.Schema({
  name: String,
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const AuthSchemaModel = mongoose.model("SkillTankAssignmentsignup", Authschema);

module.exports = {
    AuthSchemaModel
  };

const mongoose = require('mongoose');
const schema = mongoose.Schema;
const passportLocalMongoose = require('passport-local-mongoose');
const { ObjectId } = require('mongoose').Types;


const UserSchema = new schema({
    username: {
        type: String, 
        require: true,
        unique: true,
    },
    firstName: {
        type: String,
        require: true,
    }, 
    lastName: {
        type: String,
        require: true,
    },
    phoneNumber: {
        type: String,
        require: true,
    },

    resetPasswordToken: String,
    resetPasswordExpires: Date,

    files: [
        {
            filename: { type: String, required: true },
            url: { type: String, required: true },
            uploadedAt: { type: Date, default: Date.now }
        }
    ],
},
    { timestamps: true }
)

UserSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('User', UserSchema);

const mongoose = require('mongoose');
const schema = mongoose.Schema;
const { ObjectId } = require('mongoose').Types;

const PromptSchema = new schema({
    prompt: {
        type: String,
        require: true,
    },
    name: {
        type: String,
        require: true,
    },
    isSelected: {
        type: Boolean,
        require: true,
        default: false
    },
    user: {
        type: ObjectId,
        ref: 'User', // Reference to the User model
        required: true, // Make this field required to ensure association
    }
},
    { timestamps: true }
)

module.exports = mongoose.model('Prompt', PromptSchema);

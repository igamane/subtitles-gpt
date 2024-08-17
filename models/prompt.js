const mongoose = require('mongoose');
const schema = mongoose.Schema;


const PromptSchema = new schema({
    prompt: {
        type: String,
        require: true,
    },
    isSelected: {
        type: Boolean,
        require: true,
        default: false
    }
},
    { timestamps: true }
)

module.exports = mongoose.model('Prompt', PromptSchema);

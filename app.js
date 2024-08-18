if (process.env.NODE_ENV !== "production") {
    require('dotenv').config();
}

const express = require('express');
const app = express();
const path = require('path');
const mongoose = require('mongoose');
const User = require('./models/user');
const Prompt = require('./models/prompt');
const bodyParser = require('body-parser');
const port = 4000;
const ejsMate = require('ejs-mate');
const session = require('express-session');
const flash = require('connect-flash');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MongoDBStore = require('connect-mongo');
const mongoSanitize = require('express-mongo-sanitize');
const preRegistration = require('./middleware/preRegistration');
const catchAsync = require('./utils/catchAsync');
const ExpressError = require('./utils/ExpressError');
const isAuthenticated = require('./middleware/isAuthenticated');
const isAdmin = require('./middleware/isAdmin');
const nodemailer = require("nodemailer");
const hbs = require('nodemailer-express-handlebars');
const async = require("async");
const crypto = require("crypto");
const stream = require('stream');
const { OpenAI } = require('openai');
const { promisify } = require('util');
const { threadId } = require('worker_threads');
const pipeline = promisify(require('stream').pipeline);
const multer = require('multer');
const xlsx = require('xlsx');
const ExcelJS = require('exceljs');
const fs = require('fs');
const cheerio = require('cheerio');
const { storage, bucketName } = require('./storage');
const moment = require('moment');

// Generate unique filename
function generateUniqueFilename(user, extension = '.xlsx') {
    const dateTime = moment().format('YYYY-MM-DD_HH-mm');
    return `revisedTranslation-${user.firstName}-${user.lastName}-${dateTime}${extension}`;
}


// Upload file to Google Cloud Storage
async function uploadToGoogleCloud(filePath, destFileName) {
    await storage.bucket(bucketName).upload(filePath, {
        destination: destFileName,
    });

    console.log(`${filePath} uploaded to ${bucketName}`);

    // Generate a signed URL valid for 1 year
    const [url] = await storage.bucket(bucketName).file(destFileName).getSignedUrl({
        action: 'read',
        expires: Date.now() + 365 * 24 * 60 * 60 * 1000, // 1 year expiration
    });

    return url;
}

const upload = multer({ dest: 'uploads/' });


const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY // This is also the default, can be omitted
});

const admin = process.env.admin;
const dbUrl = process.env.DB_URL;

mongoose.connect(dbUrl
).then(() => {
    console.log("connect to Prompts data base");
}).catch((err) => {
    console.log("error wit connectiong", err);
})

app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.json());


const secret = 'thisshouldbeabettersecret!';

const store = new MongoDBStore({
    mongoUrl: dbUrl,
    secret,
    touchAfter: 24 * 60 * 60
});

store.on("error", function (e) {
    console.log("SESSION STORE ERROR", e)
})

const sessionConfig = {
    store,
    name: 'sesion',
    secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        // secure: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7,
    }
}

app.use(session(sessionConfig));
app.use(flash());

app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
})

app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));

// passport.serializeUser(User.serializeUser);
// passport.deserializeUser(User.deserializeUser);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id)
        .then(user => {
            done(null, user);
        })
        .catch(err => {
            done(err);
        });
});

app.get('/', (req, res) => {
    res.render('welcome')
})

// =======================Sign Up ===============
app.get('/signup', (req, res) => {
    res.render('signup')
})

app.post('/signup', preRegistration, catchAsync(async (req, res, next) => {
    try {
        const { firstName, lastName, username, phoneNumber, password } = req.body;

        let user = new User({ username, firstName, lastName, phoneNumber });
        const registredUser = await User.register(user, password);
        console.log(registredUser);
        console.log(admin)

        if (registredUser.username == admin) {
            req.login(registredUser, (err) => {
                if (err) return next(err);
                res.redirect('/admin');
            })
        } else {
            req.login(registredUser, (err) => {
                if (err) return next(err);
                res.redirect('/dashboard');
            })
        }
    } catch (e) {
        req.flash('error', e.message);
        console.log(e);
        res.redirect('/signup');
    }
}))

// ====================== Login =================
app.get('/login', (req, res) => {
    res.render('login')
})

app.post('/login', preRegistration, passport.authenticate('local', { failureFlash: true, failureRedirect: '/login' }), (req, res) => {
    console.log("Login successful");
    res.redirect('/dashboard');
});

// ====================== Log Out =================
app.get('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/signup');
    });
});

// ====================== Forgot =================
app.get('/forgot', (req, res) => {
    res.render('forgot')
});

app.post('/forgot', (req, res, next) => {
    async.waterfall([
        function (done) {
            crypto.randomBytes(20, function (err, buf) {
                let token = buf.toString('hex');
                done(err, token);
            });
        },
        function (token, done) {
            User.findOne({ username: req.body.username }).then(user => {
                if (!user) {
                    req.flash('error', 'No account exists with this email address');
                    return res.redirect('/forgot');
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save().then(() => {
                    done(null, token, user);
                }).catch(err => {
                    done(err);
                });
            }).catch(err => {
                done(err);
            });
        },
        function (token, user, done) {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                port: 587,
                secure: false,
                auth: {
                    user: process.env.GMAILAC,
                    pass: process.env.GMAILPW
                }
            });

            smtpTransport.use('compile', hbs({
                viewEngine: 'express-handlebars',
                viewEngine: {
                    extName: ".handlebars",
                    defaultLayout: false,
                    partialsDir: './views/'
                },
                viewPath: './views/',
                extName: ".handlebars"
            }));

            let mailOptions = {
                to: user.username,
                from: process.env.GMAILAC,
                subject: "Forgot your password?",
                template: 'resetemail',
                context: {
                    link: 'http://' + req.headers.host + '/reset/' + token
                }
            };
            smtpTransport.sendMail(mailOptions, function (err) {
                done(err, 'done');
            });
        }
    ], function (err) {
        if (err) return next(err);
        req.flash('success', "A password recovery link has been sent.");
        res.redirect('/forgot');
    });
});

// ======================= Reset ===============

app.get('/reset/:token', function (req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } })
        .then(user => {
            if (!user) {
                req.flash('error', "The password reset link is invalid or has expired.");
                return res.redirect('/forgot');
            }
            res.render('reset', { token: req.params.token });
        })
        .catch(err => {
            // Handle any errors that occur during the query
            console.error(err);
            res.status(500).send('An error occurred while processing your request.');
        });
});

app.post('/reset/:token', function (req, res) {
    async.waterfall([
        function (done) {
            User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } })
                .then(user => {
                    if (!user) {
                        req.flash('error', "The password reset link is invalid or has expired.");
                        return res.redirect('/forgot');
                    }
                    if (req.body.password === req.body.confirmPassword) {
                        user.setPassword(req.body.password, function (err) {
                            if (err) {
                                console.error(err);
                                return res.status(500).send('An error occurred while setting the password.');
                            }
                            user.resetPasswordToken = undefined;
                            user.resetPasswordExpires = undefined;

                            user.save()
                                .then(() => {
                                    req.logIn(user, function (err) {
                                        if (err) {
                                            console.error(err);
                                            return res.status(500).send('An error occurred while logging in the user.');
                                        }
                                        done(null, user);
                                    });
                                })
                                .catch(err => {
                                    console.error(err);
                                    res.status(500).send('An error occurred while saving the user.');
                                });
                        });
                    } else {
                        req.flash("error", "The passwords do not match.");
                        fakeurl = "/reset/" + req.params.token;
                        return res.redirect(fakeurl);
                    }
                })
                .catch(err => {
                    console.error(err);
                    res.status(500).send('An error occurred while processing your request.');
                });
        }
    ], function (err) {
        req.flash('success', "Password changed successfully.");
        res.redirect('/dashboard');
    });
});

// ====================== Reset Password =================
app.put('/settings/:id/changepassword', isAuthenticated, catchAsync(async (req, res) => {
    const author = await User.findById(req.params.id);
    if (!author._id.equals(req.user._id)) {
        return res.redirect('dashboard');
    }

    User.findById(req.params.id)
        .then(user => {
            if (!user) {
                req.flash('error', "No user found.");
                return res.redirect('/settings');
            }
            if (req.body.newPassword !== req.body.confirmPassword) {
                req.flash('error', "Please confirm your password.");
                return res.redirect('/settings');
            }

            user.changePassword(req.body.oldPassword, req.body.newPassword, function (err) {
                if (err) {
                    console.log(err);
                    req.flash('error', "The current password is incorrect.");
                    return res.redirect('/settings');
                }
                req.flash('success', "Password changed successfully.");
                res.redirect('/settings');
            });
        })
        .catch(err => {
            console.error(err);
            req.flash('error', "An error occurred while searching for the user.");
            res.redirect('/settings');
        });

}));

// ======================= User ===============
app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const userInfo = await User.findById(req.user._id);
        let isAdmin = false;
        if (userInfo.username == admin) {
            isAdmin = true;
        }
        if (!userInfo) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.render('userDashboard', { userInfo, isAdmin });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
})


function create_revised_translation_table(revisedTranslationObject, originalRows, revisedData) {
    console.log("Revised Translation Table:");
    
    const revisedTranslationArray = revisedTranslationObject.revisedTranslation;
    
    revisedTranslationArray.forEach((row, index) => {
        const newRow = {
            "In-cue/Out-cue": originalRows[index]['In-cue/Out-cue'],
            "Source": originalRows[index]['Source'],
            "Translation": originalRows[index]['Translation'],
            "Edited Translation": row[0],
            "Explanation": row[1],
            "Edit Type": row[2]
        };
        revisedData.push(newRow);  // Add the revised row to the collection
    });
}

// Validation function for correct number of rows and exactly 3 columns
function validateFunctionArgs(revisedTranslation, expectedRowCount) {
    if (!Array.isArray(revisedTranslation)) return false;
    if (revisedTranslation.length !== expectedRowCount) return false;
    for (const row of revisedTranslation) {
        if (!Array.isArray(row) || row.length !== 3) return false;
    }
    return true;
}


async function processFile(firstThreeRows, originalRows, revisedData, activePrompt) {
    try {
        // Set the active prompt or use the default if no active prompt is available
        activePromptText = activePrompt ? activePrompt.prompt : "Please proofread and edit the subtitle translation for Traditional Chinese Taiwan. Make sure it's Chinese Taiwan, not Traditional Chinese Hong Kong. Please explain the changes and their type in english not chinese (typos, grammar, accuracy, fluency, formatting). Your response should be formatted in a table using the 'create_revised_translation_table' function, containing 3 columns: Edited Translation, Explanation in english, Edit Type in english.";

        let translationText = firstThreeRows.map((row, index) => {
            return `${index + 1}. ${row.Source}\n${row.Translation}`;
        }).join("\n\n");

        console.log(translationText);

        const prompt = `${translationText}\n\n${activePromptText}`;

        console.log(prompt);

        console.log(prompt);

        let messages = [
            {
                "role": "user",
                "content": prompt
            }
        ];

        const tools = [
            {
                "type": "function",
                "function": {
                    "name": "create_revised_translation_table",
                    "description": "This function generates a table for the revised subtitle translation. The table is formatted to include three columns: Edited Translation, Explanation, and Edit Type. Each row in the table corresponds to a specific change made during the proofreading and editing process of the Traditional Chinese (Taiwan) subtitles.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "revisedTranslation": {
                                "type": "array",
                                "description": "a 2D array containing exactly X rows (where x is the number of subtitle lines) and 3 columns values of the revised translation table containing 3 columns: Edited Translation, Explanation in english, Edit Type in english",
                                "items": {
                                    "type": "string",
                                    "description": "contain the value of the corresponding table cell"
                                }
                            }
                        },
                        "required": [
                            "revisedTranslation"
                        ]
                    }
                }
            }
        ];

        const response = await openai.chat.completions.create({
            model: "gpt-4o",
            messages: messages,
            tools: tools,
            tool_choice: { "type": "function", "function": { "name": "create_revised_translation_table" } },
        });
        const responseMessage = response.choices[0].message;

        let functionResponse;

        const toolCalls = responseMessage.tool_calls;
        if (responseMessage.tool_calls) {
            const availableFunctions = {
                create_revised_translation_table: (args) => create_revised_translation_table(args, originalRows, revisedData),
            };
            messages.push(responseMessage);
            for (const toolCall of toolCalls) {
                const functionName = toolCall.function.name;
                const functionToCall = availableFunctions[functionName];
                const functionArgs = JSON.parse(toolCall.function.arguments);
                console.log(functionArgs);
                
                // Get the expected number of rows from the input data (firstThreeRows)
                const expectedRowCount = firstThreeRows.length;

                // Validation check for the correct number of rows and 3 columns
                const isValid = validateFunctionArgs(functionArgs.revisedTranslation, expectedRowCount);

                if (isValid) {
                    console.log('valid');
                    await functionToCall(functionArgs);
                    messages.push({
                        tool_call_id: toolCall.id,
                        role: "tool",
                        name: functionName,
                        content: functionArgs,
                    });
                } else {
                    console.warn('Invalid functionArgs: Retrying for the same batch.');
                    // Retry by calling the same function again for the current batch
                    return await processFile(firstThreeRows, originalRows, revisedData);
                }
            }
            return functionResponse;
        }
    } catch (err) {
        console.error('Error:', err);
    }
}

const clients = []; // Store connected clients

// Add a new endpoint to handle SSE
app.get('/progress', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // Add this client to the list
    clients.push(res);

    // Remove the client when they disconnect
    req.on('close', () => {
        clients.splice(clients.indexOf(res), 1);
    });
});

function sendProgressUpdate(processedLines, totalLines) {
    const progressMessage = `${processedLines}/${totalLines}`; // Send as "processed/total"
    clients.forEach(client => client.write(`data: ${progressMessage}\n\n`));
}

// Function to check if the cell value should be bold
function shouldBeBold(value) {
    const boldWords = ['grammar', 'accuracy', 'typos', 'Grammar', 'Accuracy', 'Typos'];

    // Split the cell value by commas and trim any whitespace
    const words = value.split(',').map(word => word.trim());

    // Check if any of the words in the cell match the bold words
    return words.some(word => boldWords.includes(word));
}


app.post('/excel-file', upload.single('file'), async (req, res) => {
    try {
        // Get the userId from the request
        const userId = req.user._id;

        // Fetch user from the database
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Find the active prompt associated with the user
        const activePrompt = await Prompt.findOne({ user: userId, isSelected: true });

        // Read the uploaded Excel file
        const workbook = xlsx.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const worksheet = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        let revisedData = []; // This will hold all the revised translations
        const totalLines = worksheet.length;

        let i = 0;
        while (i < worksheet.length) {
            const batch = worksheet.slice(i, i + 3); // Get 3 rows at a time
            const firstThreeRows = batch.map(row => ({
                'In-cue/Out-cue': row['In-cue/Out-cue'] || 'N/A', // Fallback value for the time code
                Source: row['Source'] || row['source'] || 'N/A', // Fallback value for source
                Translation: row['Translation'] || row['translation'] || 'N/A' // Fallback value for translation
            }));

            // Process the batch
            await processFile(firstThreeRows, batch, revisedData, activePrompt);

            i += 3; // Move to the next set of rows

            // Send progress update
            sendProgressUpdate(i, totalLines);
        }

        // Create an XLSX workbook and sheet from the revised data
        const xlsxWorkbook = xlsx.utils.book_new();
        const xlsxWorksheet = xlsx.utils.json_to_sheet(revisedData);
        xlsx.utils.book_append_sheet(xlsxWorkbook, xlsxWorksheet, 'Revised Translations');

        // Write the XLSX workbook to a temporary file
        const tempXlsxPath = `/tmp/revised-file.xlsx`;
        xlsx.writeFile(xlsxWorkbook, tempXlsxPath);

        // Now load the temporary XLSX file into ExcelJS for further formatting
        const excelWorkbook = new ExcelJS.Workbook();
        await excelWorkbook.xlsx.readFile(tempXlsxPath);
        const worksheetExcelJS = excelWorkbook.getWorksheet('Revised Translations');

        // Apply bold formatting where necessary
        worksheetExcelJS.eachRow((row, rowIndex) => {
            row.eachCell({ includeEmpty: true }, (cell, colIndex) => {
                if (shouldBeBold(cell.value)) {
                    cell.font = { bold: true };
                }
            });
        });

        // Generate a unique filename using the user's first and last name
        const uniqueFilename = generateUniqueFilename(user);
        const tempFilePath = `/tmp/${uniqueFilename}`;

        // Save the ExcelJS workbook to the temp file path
        await excelWorkbook.xlsx.writeFile(tempFilePath);

        // Upload to Google Cloud Storage
        const fileUrl = await uploadToGoogleCloud(tempFilePath, uniqueFilename);

        // Attach the file URL to the user in MongoDB
        await User.updateOne(
            { _id: userId },
            { $push: { files: { filename: uniqueFilename, url: fileUrl } } }
        );

        res.json({ message: 'Processing complete!', fileUrl });
    } catch (err) {
        console.error('Error processing Excel file:', err);
        res.status(500).json({ error: 'Failed to process file' });
    }
});




function extractSubtitlesFromHTML(htmlContent) {
    const $ = cheerio.load(htmlContent);

    // Extract rows
    const rows = [];
    $('table tbody tr').each((index, element) => {
        const cells = $(element).find('td');
        const inCueOutCue = $(cells[0]).text().trim();
        const source = $(cells[1]).text().trim();
        const translation = $(cells[2]).text().trim();
        rows.push({
            'In-cue/Out-cue': inCueOutCue,
            Source: source,
            Translation: translation
        });
    });
    return rows;
}

app.post('/html-file', upload.single('file'), async (req, res) => {
    try {
        // Get the userId from the request
        const userId = req.user._id;

        // Fetch user from the database
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Find the active prompt associated with the user
        const activePrompt = await Prompt.findOne({ user: userId, isSelected: true });

        // Load the uploaded HTML file
        const htmlContent = fs.readFileSync(req.file.path, 'utf-8');

        // Extract subtitles from the HTML content
        const worksheet = extractSubtitlesFromHTML(htmlContent);

        let revisedData = []; // This will hold all the revised translations
        const totalLines = worksheet.length;

        let i = 0;
        while (i < worksheet.length) {
            const batch = worksheet.slice(i, i + 3); // Get 3 rows at a time
            const firstThreeRows = batch.map(row => ({
                'In-cue/Out-cue': row['In-cue/Out-cue'] || 'N/A', // Fallback value for the time code
                Source: row['Source'] || row['source'] || 'N/A', // Fallback value for source
                Translation: row['Translation'] || row['translation'] || 'N/A' // Fallback value for translation
            }));

            // Process the batch
            await processFile(firstThreeRows, batch, revisedData, activePrompt);

            i += 3; // Move to the next set of rows

            // Send progress update
            sendProgressUpdate(i, totalLines);
        }

        // Create a new ExcelJS workbook and worksheet
        const workbook = new ExcelJS.Workbook();
        const worksheetExcelJS = workbook.addWorksheet('Revised Translations');

        // Add headers (titles) for the columns and apply bold formatting
        const headers = ['In-cue/Out-cue', 'Source', 'Original Translation', 'Edited Translation', 'Explanation', 'Edit Type'];
        const headerRow = worksheetExcelJS.addRow(headers);

        // Apply bold formatting to the header row
        headerRow.eachCell((cell) => {
            cell.font = { bold: true };
        });

        // Add the revised data to the worksheet
        revisedData.forEach((row) => {
            const newRow = worksheetExcelJS.addRow([
                row['In-cue/Out-cue'],
                row['Source'],
                row['Translation'],
                row['Edited Translation'],
                row['Explanation'],
                row['Edit Type']
            ]);

            // Apply bold formatting to specific cells based on the content
            newRow.eachCell((cell, colNumber) => {
                if (shouldBeBold(cell.value)) {
                    cell.font = { bold: true };
                }
            });
        });

        // Generate a unique filename using the user's first and last name
        const uniqueFilename = generateUniqueFilename(user);
        const tempFilePath = `/tmp/${uniqueFilename}`;

        // Save the ExcelJS workbook to the temp file path
        await workbook.xlsx.writeFile(tempFilePath);

        // Upload to Google Cloud Storage
        const fileUrl = await uploadToGoogleCloud(tempFilePath, uniqueFilename);

        // Attach the file URL to the user in MongoDB
        await User.updateOne(
            { _id: userId },
            { $push: { files: { filename: uniqueFilename, url: fileUrl } } }
        );

        res.json({ message: 'Processing complete!', fileUrl });
    } catch (err) {
        console.error('Error processing HTML file:', err);
        res.status(500).json({ error: 'Failed to process file' });
    }
});



app.get('/files', isAuthenticated, async (req, res) => {
    try {
        const userInfo = await User.findById(req.user._id);
        let isAdmin = false;
        if (userInfo.username == admin) {
            isAdmin = true;
        }
        if (!userInfo) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.render('files', { userInfo, isAdmin });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
})

// ======================= Settings ===============
app.get('/settings', isAuthenticated, async (req, res) => {
    const userInfo = await User.findById(req.user._id);
    res.render('settings', { userInfo })
})

app.put('/settings/:id/edit', isAuthenticated, catchAsync(async (req, res, next) => {
    const author = await User.findById(req.params.id);
    if (!author._id.equals(req.user._id)) {
        return res.redirect('dashboard');
    }
    let user;
    user = await User.findByIdAndUpdate(req.params.id, { ...req.body });
    const updatedAuthor = await User.findById(req.params.id);
    req.login(updatedAuthor, (err) => {
        if (err) return next(err);
        req.flash('success', "The information has been successfully updated.");
        res.redirect('/settings')
    })
}));

app.get('/admin', isAdmin, async (req, res) => {
    try {
        const userInfo = await User.findById(req.user._id);
        let isAdmin = false;
        if (userInfo.username == admin) {
            isAdmin = true;
        }
        const users = await User.find({});

        res.render('admin', {users, isAdmin});
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
})
app.get('/prompt', isAuthenticated, async (req, res) => {
    try {
        const userInfo = await User.findById(req.user._id);
        let isAdmin = false;
        if (userInfo.username == admin) {
            isAdmin = true;
        }
        // Get the logged-in user's ID
        const userId = req.user._id;

        // Check if the database is empty for this user
        const promptCount = await Prompt.countDocuments({ user: userId });

        if (promptCount === 0) {
            // If empty, insert the first prompt associated with the user
            const firstPrompt = new Prompt({
                prompt: "Please proofread and edit the subtitle translation for Traditional Chinese Taiwan. Make sure it's Chinese Taiwan, not Traditional Chinese Hong Kong. Please explain the changes and their type in english not chinese (typos, grammar, accuracy, fluency, formatting). Your response should be formatted in a table using the 'create_revised_translation_table' function, containing 3 columns: Edited Translation, Explanation in english, Edit Type in english.",
                name: "Default Prompt",
                isSelected: true,
                user: userId // Associate with the logged-in user
            });

            await firstPrompt.save();
        }

        // Fetch all prompts associated with the logged-in user
        const prompts = await Prompt.find({ user: userId });

        // Render the 'prompt' view with the retrieved prompts
        res.render('prompt', { prompts, isAdmin });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});



app.post('/prompt', isAuthenticated, async (req, res) => {
    try {
        const { prompt, promptName } = req.body;
        const userId = req.user._id; // Get the logged-in user's ID

        // Create a new Prompt document associated with the user
        const newPrompt = new Prompt({
            prompt: prompt,
            name: promptName,
            isSelected: false, // Default value
            user: userId // Associate with the logged-in user
        });

        // Save the document to the database
        await newPrompt.save();

        // Redirect or send a response
        res.redirect('/prompt'); // Redirect to the homepage or another route
    } catch (error) {
        console.error('Error creating prompt:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.put('/prompt/:id', isAuthenticated, async (req, res) => {
    try {
        const { prompt, promptName, isActive } = req.body;
        const userId = req.user._id; // Get the logged-in user's ID

        if (isActive === 'on') {
            // If the current prompt is being activated, deactivate all other prompts for this user
            await Prompt.updateMany({ user: userId }, { isSelected: false });
        }

        // Find the prompt by ID and user ID, then update its fields
        await Prompt.findOneAndUpdate(
            { _id: req.params.id, user: userId },
            {
                prompt: prompt,
                name: promptName,
                isSelected: isActive === 'on' // Convert checkbox value to boolean
            }
        );

        // Redirect or send a response after updating
        res.redirect('/prompt');
    } catch (error) {
        console.error('Error updating prompt:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});

app.delete('/prompt/:id', isAuthenticated, async (req, res) => {
    try {
        const userId = req.user._id; // Get the logged-in user's ID
        const promptId = req.params.id; // Get the prompt's ID from the URL parameters

        // Find the prompt by ID and user ID, then delete it
        const deletedPrompt = await Prompt.findOneAndDelete({ _id: promptId, user: userId });

        if (!deletedPrompt) {
            return res.status(404).json({ message: 'Prompt not found or not authorized to delete this prompt.' });
        }

        // Redirect or send a response after deletion
        res.redirect('/prompt');
    } catch (error) {
        console.error('Error deleting prompt:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
});



app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
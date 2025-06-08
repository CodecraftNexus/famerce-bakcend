const mongoose = require('mongoose');
const uri = "mongodb+srv://root:19raYpRTQNR6jfUB@cluster0.zyw3wom.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('Connection error:', err));

// ඔබේ schema සහ model define කරන්න
const Schema = mongoose.Schema;
const userSchema = new Schema({ name: String });
const User = mongoose.model('User', userSchema);

// උදාහරණය: User එකක් save කිරීම
const newUser = new User({ name: 'Test User' });
newUser.save().then(() => console.log('User saved'));
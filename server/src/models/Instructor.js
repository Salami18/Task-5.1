import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
//
// NOTE (security lab): this model is intentionally insecure. Passwords are
// stored in PLAINTEXT (never do this in real code) so that the NoSQL injection
// lab can demonstrate blind $regex password extraction. The apiKey / private
// contact fields are "trophy" data that filter-injection attacks can leak.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    // ⚠️ VULNERABLE (lab): plaintext password, no bcrypt hashing.
    password: { type: String, required: true },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive "trophy" fields the directory hides but injection can leak.
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);

instructorSchema.pre('save', async function (next) {
  // If the password hasn't changed (e.g., updating email), skip hashing
  if (!this.isModified('password')) return next();

  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    //const hashPass = this.password;
    next();
  } catch (error) {
    next(error);
  }
});

export const Instructor = mongoose.model('Instructor', instructorSchema);

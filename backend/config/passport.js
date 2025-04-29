const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('../models/User');

const BASE_URL = process.env.BASE_URL;

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/api/auth/google/callback`,
  passReqToCallback: true,
},
  async (req, accessToken, refreshToken, profile, done) => {
    try {
      const googleEmail = profile.emails[0].value;
      const googleName = profile.displayName;
      const profilePic = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

      if (!googleEmail || !googleName) {
        return done(null, false, { message: 'Could not retrieve user info from Google profile' });
      }

      let user = await User.findOne({ email: googleEmail });

      if (!user) {
        user = new User({
          name: googleName,
          email: googleEmail,
          profilePic: profilePic,
          password: 'googleAuthPassword' + Date.now(), // Make it unique and more secure
        });
        await user.save();
      } else {
        if (profilePic && !user.profilePic) {
          user.profilePic = profilePic;
          await user.save();
        }
      }

      return done(null, user);

    } catch (error) {
      console.error("Error in Google authentication strategy:", error);
      return done(error);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = passport; 
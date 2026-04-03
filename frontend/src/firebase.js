// frontend/src/firebase.js
//
// Firebase initialisation + Google sign-in helper.
// Import { auth, signInWithGoogle, signOut } from './firebase'

import { initializeApp } from "firebase/app";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut as firebaseSignOut,
  onAuthStateChanged,
} from "firebase/auth";

const firebaseConfig = {
  apiKey:            "AIzaSyBuMBEhjNeQ7l9i0ySt0tWvqv6AOzavm3g",
  authDomain:        "api-testing-platform-fdc71.firebaseapp.com",
  projectId:         "api-testing-platform-fdc71",
  storageBucket:     "api-testing-platform-fdc71.firebasestorage.app",
  messagingSenderId: "809957617111",
  appId:             "1:809957617111:web:85c507b620665d1cee2f92",
};

const app      = initializeApp(firebaseConfig);
export const auth = getAuth(app);

const provider = new GoogleAuthProvider();
provider.setCustomParameters({ prompt: "select_account" });

// Sign in with Google popup
export const signInWithGoogle = () => signInWithPopup(auth, provider);

// Sign out
export const signOut = () => firebaseSignOut(auth);

// Subscribe to auth state changes
// Returns unsubscribe function
export const onAuth = (callback) => onAuthStateChanged(auth, callback);

// Get current user's ID token (refreshes automatically)
export const getIdToken = async () => {
  const user = auth.currentUser;
  if (!user) return null;
  return user.getIdToken();
};
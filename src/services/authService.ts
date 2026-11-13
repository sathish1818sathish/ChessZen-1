// Complete Authentication & Storage Service for ChessZen AI

import { ModeRatings, ModeStats, MatchRecord, DEFAULT_RATINGS, GameModeKey } from "../types";
import { 
  signInWithPopup, 
  signInWithRedirect,
  getRedirectResult,
  signInWithCredential, 
  GoogleAuthProvider, 
  signOut,
  FirebaseUser,
  firebaseConfig,
  auth,
  googleProvider
} from "../lib/firebase";
import { Capacitor } from "@capacitor/core";
import { FirebaseAuthentication } from "@capacitor-firebase/authentication";
import { 
  saveUserProfileToFirestore, 
  getUserProfileFromFirestore,
  getUserProfileByEmailFromFirestore,
  isUsernameTakenInFirestore
} from "./firestoreService";

export interface UserSettings {
  theme: string;
  soundEnabled: boolean;
  coachMode: boolean;
  boardStyle: string;
  boardTheme?: string;
  pieceStyle?: string;
}

export interface StoredUser {
  id: string;
  uid?: string;
  username: string;
  email: string;
  passwordHash: string; // SHA-256 hashed password
  profilePicture: string;
  profileImageUrl?: string;
  level: number;
  xp: number;
  coins: number;
  rating: number;
  elo: number;
  puzzleElo: number;
  ratings: ModeRatings;
  modeStats?: Record<GameModeKey, ModeStats>;
  matchHistory?: MatchRecord[];
  puzzleProgress?: Record<string, any>;
  gambitProgress?: Record<string, any>;
  boardTheme?: string;
  highestRating?: number;
  gamesPlayed?: number;
  gamesWon?: number;
  gamesLost?: number;
  wins?: number;
  losses?: number;
  draws?: number;
  puzzlesSolved?: number;
  lessonsCompleted?: number;
  gambitsCompleted?: number;
  trapsCompleted?: number;
  streak: number;
  longestStreak?: number;
  bestStreak?: number;
  lastActivityDate?: string | null;
  streakStartedAt?: string | null;
  unlockedBadges: string[];
  lastActiveDate: string | null;
  settings: UserSettings;
  createdAt: string;
}

export interface AuthSession {
  token: string;
  user: Omit<StoredUser, 'passwordHash'>;
  expiresAt: number;
}

const USERS_DB_KEY = "chesszen_users_db";
const CURRENT_SESSION_KEY = "chesszen_current_session";
const OTP_STORE_KEY = "chesszen_otp_verification_store";

// Helper: Password Hashing using SHA-256 Web Crypto API
export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "_chesszen_salt_v1");
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Seed default users if DB is empty
export async function initializeUserDatabase(): Promise<StoredUser[]> {
  const existing = localStorage.getItem(USERS_DB_KEY);
  if (existing) {
    try {
      return JSON.parse(existing);
    } catch {
      // Fallback if corrupt
    }
  }

  const initialUsers: StoredUser[] = [];
  localStorage.setItem(USERS_DB_KEY, JSON.stringify(initialUsers));
  return initialUsers;
}

// Get all stored users
export function getStoredUsers(): StoredUser[] {
  const raw = localStorage.getItem(USERS_DB_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

// Save users DB
function saveUsersDB(users: StoredUser[]): void {
  localStorage.setItem(USERS_DB_KEY, JSON.stringify(users));
}

// Validation Helpers
export function validateEmailFormat(email: string): boolean {
  if (!email || !email.trim()) return true; // Email optional if username is primary
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

export function isUsernameAvailable(username: string): boolean {
  const cleaned = username.trim().toLowerCase();
  if (cleaned.length < 3) return false;
  // Check alphanumeric + underscore/hyphen
  if (!/^[a-zA-Z0-9_-]+$/.test(cleaned)) return false;
  const users = getStoredUsers();
  return !users.some((u) => u.username.toLowerCase() === cleaned);
}

export function isEmailAvailable(email: string): boolean {
  const cleaned = email.trim().toLowerCase();
  if (!cleaned) return true;
  const users = getStoredUsers();
  return !users.some((u) => u.email.toLowerCase() === cleaned);
}

export interface PasswordStrengthResult {
  score: number; // 0 to 5
  label: "Weak" | "Medium" | "Strong";
  checks: {
    length: boolean;
    uppercase: boolean;
    lowercase: boolean;
    number: boolean;
    special: boolean;
  };
}

export function evaluatePasswordStrength(password: string): PasswordStrengthResult {
  const checks = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[^A-Za-z0-9]/.test(password)
  };

  let score = 0;
  if (checks.length) score++;
  if (checks.uppercase) score++;
  if (checks.lowercase) score++;
  if (checks.number) score++;
  if (checks.special) score++;

  let label: "Weak" | "Medium" | "Strong" = "Weak";
  if (score >= 3 && score < 5) label = "Medium";
  if (score === 5) label = "Strong";

  return { score, label, checks };
}

// User Registration
export async function registerNewUser(
  username: string,
  email: string,
  password: string,
  profilePicture?: string
): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  await initializeUserDatabase();
  const users = getStoredUsers();

  const cleanEmail = email && email.trim() ? email.trim().toLowerCase() : "";
  let cleanUsername = username.trim();
  if (!cleanUsername && cleanEmail) {
    cleanUsername = extractUsernameFromEmail(cleanEmail);
  }

  if (cleanUsername.length < 2) {
    throw new Error("Username must be at least 2 characters long.");
  }

  // Generate deterministic UID based on email or unique identifier
  const permanentUid = cleanEmail 
    ? ("usr_" + cleanEmail.replace(/[^a-zA-Z0-9]/g, "_"))
    : ("usr_" + Math.random().toString(36).substring(2, 11));

  // Check if profile already exists in Firestore or local DB for this email / uid
  const existingFsUser = await getUserProfileFromFirestore(permanentUid) || (cleanEmail ? await getUserProfileByEmailFromFirestore(cleanEmail) : null);
  const existingLocalUser = users.find((u) => u.id === permanentUid || (cleanEmail && u.email.toLowerCase() === cleanEmail));

  if (existingFsUser || existingLocalUser) {
    throw new Error("An account with this email address already exists. Please sign in instead.");
  }

  // Check if username is taken, generate unique if derived from email
  const isTaken = users.some((u) => u.username.toLowerCase() === cleanUsername.toLowerCase()) || (await isUsernameTakenInFirestore(cleanUsername));
  if (isTaken && (!username.trim() || username.trim() === cleanUsername)) {
    cleanUsername = await generateUniqueUsername(cleanUsername);
  } else if (isTaken) {
    throw new Error("Username already exists. Please choose another username.");
  }

  const finalEmail = cleanEmail || `${cleanUsername.toLowerCase()}@chesszen.com`;

  const strength = evaluatePasswordStrength(password);
  if (!strength.checks.length || !strength.checks.uppercase || !strength.checks.lowercase || !strength.checks.number || !strength.checks.special) {
    throw new Error("Password does not meet all security requirements.");
  }

  const passwordHash = await hashPassword(password);
  const avatar = profilePicture || `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(cleanUsername)}`;

  // Newly registered user starts with starting rating 1200
  const newUser: StoredUser = {
    id: permanentUid,
    username: cleanUsername,
    email: finalEmail,
    passwordHash,
    profilePicture: avatar,
    level: 1,
    xp: 0,
    coins: 0,
    rating: 1200,
    elo: 1200,
    puzzleElo: 1200,
    ratings: {
      bullet: 1200,
      blitz: 1200,
      rapid: 1200,
      classical: 1200
    },
    modeStats: {
      bullet: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
      blitz: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
      rapid: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
      classical: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 }
    },
    matchHistory: [],
    highestRating: 1200,
    gamesPlayed: 0,
    gamesWon: 0,
    gamesLost: 0,
    wins: 0,
    losses: 0,
    draws: 0,
    puzzlesSolved: 0,
    lessonsCompleted: 0,
    gambitsCompleted: 0,
    trapsCompleted: 0,
    streak: 0,
    longestStreak: 0,
    bestStreak: 0,
    lastActivityDate: null,
    streakStartedAt: null,
    unlockedBadges: [],
    lastActiveDate: new Date().toISOString().split("T")[0],
    settings: {
      theme: "tournament",
      soundEnabled: true,
      coachMode: true,
      boardStyle: "tournament"
    },
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  saveUsersDB(users);

  // Synchronize with Firestore Database
  try {
    await saveUserProfileToFirestore(newUser);
  } catch (err) {
    console.warn("Firestore sync warning during register:", err);
  }

  syncLegacyUserProfile(newUser);

  const { passwordHash: _, ...userWithoutHash } = newUser;
  const token = "token_" + Math.random().toString(36).substring(2, 15) + Date.now();

  return { user: userWithoutHash, token };
}

// User Sign In (Supports Username OR Email)
export async function signInUser(
  usernameOrEmail: string,
  password: string,
  rememberMe: boolean = true
): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  await initializeUserDatabase();
  const users = getStoredUsers();
  const query = usernameOrEmail.trim().toLowerCase();

  let foundUser = users.find(
    (u) => u.email.toLowerCase() === query || u.username.toLowerCase() === query
  );

  const computedHash = await hashPassword(password);

  if (!foundUser) {
    // If not found in local DB, attempt lookup in Firestore
    const candidateUid = "usr_" + query.replace(/[^a-zA-Z0-9]/g, "_");
    const fsProfile = await getUserProfileFromFirestore(candidateUid) || await getUserProfileByEmailFromFirestore(query);
    if (fsProfile) {
      // Reconstruct local record from Firestore
      const restoredUser: StoredUser = {
        id: fsProfile.id || candidateUid,
        username: fsProfile.username || extractUsernameFromEmail(query),
        email: fsProfile.email || query,
        passwordHash: computedHash,
        profilePicture: fsProfile.profilePicture || `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(fsProfile.username || query)}`,
        level: fsProfile.level || 1,
        xp: fsProfile.xp || 0,
        coins: fsProfile.coins || 0,
        rating: fsProfile.rating ?? fsProfile.elo ?? 1200,
        elo: fsProfile.elo ?? fsProfile.rating ?? 1200,
        puzzleElo: fsProfile.puzzleElo ?? 1200,
        ratings: fsProfile.ratings || { bullet: 1200, blitz: 1200, rapid: 1200, classical: 1200 },
        modeStats: fsProfile.modeStats || {
          bullet: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          blitz: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          rapid: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          classical: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 }
        },
        matchHistory: fsProfile.matchHistory || [],
        highestRating: fsProfile.highestRating || fsProfile.rating || 1200,
        gamesPlayed: fsProfile.gamesPlayed || 0,
        gamesWon: fsProfile.gamesWon || fsProfile.wins || 0,
        gamesLost: fsProfile.gamesLost || fsProfile.losses || 0,
        wins: fsProfile.wins || fsProfile.gamesWon || 0,
        losses: fsProfile.losses || fsProfile.gamesLost || 0,
        draws: fsProfile.draws || 0,
        puzzlesSolved: fsProfile.puzzlesSolved || 0,
        lessonsCompleted: fsProfile.lessonsCompleted || 0,
        gambitsCompleted: fsProfile.gambitsCompleted || 0,
        trapsCompleted: fsProfile.trapsCompleted || 0,
        streak: fsProfile.streak || 0,
        longestStreak: fsProfile.longestStreak || 0,
        bestStreak: fsProfile.bestStreak || 0,
        lastActivityDate: fsProfile.lastActivityDate || null,
        streakStartedAt: fsProfile.streakStartedAt || null,
        unlockedBadges: fsProfile.unlockedBadges || [],
        lastActiveDate: new Date().toISOString().split("T")[0],
        settings: fsProfile.settings || {
          theme: "tournament",
          soundEnabled: true,
          coachMode: true,
          boardStyle: "tournament"
        },
        createdAt: fsProfile.createdAt || new Date().toISOString()
      };
      users.push(restoredUser);
      saveUsersDB(users);
      foundUser = restoredUser;
    } else {
      throw new Error("Account not found. Please check your username or create a new account.");
    }
  }

  if (computedHash !== foundUser.passwordHash && foundUser.passwordHash !== "google_authenticated_oauth") {
    throw new Error("Incorrect password. Please try again.");
  }

  // Retrieve persistent profile directly from Firestore to ensure latest values are loaded
  try {
    const fsProfile = await getUserProfileFromFirestore(foundUser.id) || await getUserProfileByEmailFromFirestore(foundUser.email);
    if (fsProfile) {
      const savedElo = fsProfile.rating ?? fsProfile.elo ?? foundUser.rating ?? 1200;
      foundUser.rating = savedElo;
      foundUser.elo = savedElo;
      foundUser.puzzleElo = fsProfile.puzzleElo ?? foundUser.puzzleElo ?? 1200;
      foundUser.ratings = fsProfile.ratings || foundUser.ratings || { bullet: 1200, blitz: 1200, rapid: 1200, classical: 1200 };
      foundUser.modeStats = fsProfile.modeStats || foundUser.modeStats;
      foundUser.matchHistory = fsProfile.matchHistory || foundUser.matchHistory || [];
      foundUser.gamesPlayed = fsProfile.gamesPlayed ?? foundUser.gamesPlayed ?? 0;
      foundUser.wins = fsProfile.wins ?? (fsProfile as any).gamesWon ?? foundUser.wins ?? 0;
      foundUser.losses = fsProfile.losses ?? (fsProfile as any).gamesLost ?? foundUser.losses ?? 0;
      foundUser.draws = fsProfile.draws ?? foundUser.draws ?? 0;
      foundUser.level = fsProfile.level || foundUser.level || 1;
      foundUser.xp = fsProfile.xp ?? foundUser.xp ?? 0;
      foundUser.coins = fsProfile.coins ?? foundUser.coins ?? 0;
      foundUser.profilePicture = fsProfile.profilePicture || foundUser.profilePicture;
      foundUser.settings = fsProfile.settings || foundUser.settings;
      foundUser.unlockedBadges = fsProfile.unlockedBadges || foundUser.unlockedBadges || [];
    } else {
      await saveUserProfileToFirestore(foundUser);
    }
  } catch (err) {
    console.warn("Firestore sync warning during sign-in:", err);
  }

  // Update last active date
  const today = new Date().toISOString().split("T")[0];
  foundUser.lastActiveDate = today;
  saveUsersDB(users);

  syncLegacyUserProfile(foundUser);

  const { passwordHash: _, ...userWithoutHash } = foundUser;
  const token = "token_" + Math.random().toString(36).substring(2, 15) + Date.now();
  const session: AuthSession = {
    token,
    user: userWithoutHash,
    expiresAt: Date.now() + (rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000)
  };

  localStorage.setItem(CURRENT_SESSION_KEY, JSON.stringify(session));
  localStorage.setItem("chessmaster_logged_in", "true");

  return { user: userWithoutHash, token };
}

/**
 * Extracts username from email address (part before @)
 * Examples:
 * sathishk@gmail.com -> sathishk
 * john.doe@gmail.com -> john.doe
 * chessplayer123@gmail.com -> chessplayer123
 */
export function extractUsernameFromEmail(email: string): string {
  if (!email || !email.trim()) return "player";
  const trimmed = email.trim();
  const atIdx = trimmed.indexOf("@");
  if (atIdx > 0) {
    const prefix = trimmed.substring(0, atIdx).trim();
    if (prefix) return prefix;
  }
  return trimmed;
}

/**
 * Helper to generate a collision-free username for new users
 */
export async function generateUniqueUsername(baseCandidate: string): Promise<string> {
  let cleaned = (baseCandidate || "player")
    .trim()
    .replace(/\s+/g, "_")
    .replace(/[^a-zA-Z0-9._-]/g, "");

  if (!cleaned || cleaned.length < 2) {
    cleaned = "player";
  }
  if (cleaned.length > 25) {
    cleaned = cleaned.substring(0, 25);
  }

  const users = getStoredUsers();
  const isLocalTaken = (name: string) =>
    users.some((u) => u.username.toLowerCase() === name.toLowerCase());

  let isTaken = isLocalTaken(cleaned) || (await isUsernameTakenInFirestore(cleaned));

  if (!isTaken) {
    return cleaned;
  }

  // Attempt numbered suffixes: candidate01, candidate02...
  for (let i = 1; i <= 99; i++) {
    const suffix = i < 10 ? `0${i}` : `${i}`;
    const candidateWithSuffix = `${cleaned.substring(0, 23)}${suffix}`;
    const taken = isLocalTaken(candidateWithSuffix) || (await isUsernameTakenInFirestore(candidateWithSuffix));
    if (!taken) {
      return candidateWithSuffix;
    }
  }

  return `${cleaned.substring(0, 18)}_${Math.floor(1000 + Math.random() * 9000)}`;
}

/**
 * Ensures any async promise rejects cleanly after timeoutMs rather than hanging forever.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  timeoutMessage: string = "Operation timed out. Please try again."
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(timeoutMessage));
    }, timeoutMs);

    promise
      .then((res) => {
        clearTimeout(timer);
        resolve(res);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

const inFlightProfileSyncs = new Map<string, Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }>>();

/**
 * Centralized Processor for Authenticated Firebase Google User.
 * Handles Android Native (ID token), Capacitor, Redirect, and Popup flows.
 * Deduplicates concurrent calls for the same UID to prevent duplicate writes/races.
 * Preserves all existing Firestore statistics, ratings, match histories, and usernames.
 */
export async function processAuthenticatedFirebaseUser(
  googleUser: FirebaseUser | any
): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  if (!googleUser || !googleUser.uid) {
    throw new Error("Invalid authentication user payload.");
  }

  const uid = googleUser.uid;
  const existingInFlight = inFlightProfileSyncs.get(uid);
  if (existingInFlight) {
    return existingInFlight;
  }

  const syncPromise = (async () => {
    console.log("[GoogleAuth] Loading ChessZen profile for UID:", uid);
    await initializeUserDatabase();
    const users = getStoredUsers();

    const verifiedEmail = (googleUser.email || "").trim().toLowerCase();
    const displayName = (googleUser.displayName || "").trim();
    const photoURL = (googleUser.photoURL || googleUser.photoUrl || "").trim();

    // 1. Check if profile already exists in Firestore (by UID first, then email fallback)
    let fsProfile: Omit<StoredUser, 'passwordHash'> | null = null;
    try {
      const fetchProfilePromise = (async () => {
        let p = await getUserProfileFromFirestore(uid);
        if (!p && verifiedEmail) {
          p = await getUserProfileByEmailFromFirestore(verifiedEmail);
        }
        return p;
      })();
      fsProfile = await withTimeout(fetchProfilePromise, 5000, "Firestore fetch timed out");
    } catch (fsErr) {
      console.warn("Firestore lookup note (using cached/fallback profile):", fsErr);
    }

    const localFound =
      users.find((u) => u.id === uid || u.uid === uid) ||
      (verifiedEmail ? users.find((u) => u.email.toLowerCase() === verifiedEmail) : undefined);

    if (fsProfile || localFound) {
      // Existing User -> PRESERVE ALL STATS, RATINGS, HISTORY, PROGRESS AND USERNAME
      const base = fsProfile || localFound!;
      const savedElo = base.rating ?? base.elo ?? 1200;
      const existingUsername = base.username || displayName || extractUsernameFromEmail(verifiedEmail);

      // Prefer custom uploaded picture if set; otherwise refresh with Google's official photoURL
      const existingPic = (base.profilePicture || base.profileImageUrl || "").trim();
      const isGeneratedAvatar = existingPic.includes("api.dicebear.com");
      const resolvedAvatar =
        (existingPic && !isGeneratedAvatar ? existingPic : "") ||
        photoURL ||
        existingPic ||
        `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(existingUsername)}`;

      const mergedUser: StoredUser = {
        id: uid,
        uid: uid,
        username: existingUsername,
        email: verifiedEmail || base.email,
        passwordHash: localFound?.passwordHash || "google_authenticated_oauth",
        profilePicture: resolvedAvatar,
        profileImageUrl: resolvedAvatar,
        level: base.level || 1,
        xp: base.xp ?? 0,
        coins: base.coins ?? 0,
        rating: savedElo,
        elo: savedElo,
        puzzleElo: base.puzzleElo ?? 1200,
        ratings: base.ratings || { bullet: 1200, blitz: 1200, rapid: 1200, classical: 1200 },
        modeStats: base.modeStats || {
          bullet: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          blitz: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          rapid: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
          classical: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 }
        },
        matchHistory: base.matchHistory || [],
        puzzleProgress: (base as any).puzzleProgress || localFound?.puzzleProgress || {},
        gambitProgress: (base as any).gambitProgress || localFound?.gambitProgress || {},
        boardTheme: (base as any).boardTheme || base.settings?.boardTheme || localFound?.boardTheme || "tournament",
        highestRating: base.highestRating || savedElo,
        gamesPlayed: base.gamesPlayed || 0,
        gamesWon: base.gamesWon || base.wins || 0,
        gamesLost: base.gamesLost || base.losses || 0,
        wins: base.wins || base.gamesWon || 0,
        losses: base.losses || base.gamesLost || 0,
        draws: base.draws || 0,
        puzzlesSolved: base.puzzlesSolved || 0,
        lessonsCompleted: base.lessonsCompleted || 0,
        gambitsCompleted: base.gambitsCompleted || 0,
        trapsCompleted: base.trapsCompleted || 0,
        streak: base.streak ?? 0,
        longestStreak: base.longestStreak ?? base.bestStreak ?? 0,
        bestStreak: base.bestStreak ?? base.longestStreak ?? 0,
        lastActivityDate: base.lastActivityDate ?? null,
        streakStartedAt: base.streakStartedAt ?? null,
        unlockedBadges: base.unlockedBadges || [],
        lastActiveDate: new Date().toISOString().split("T")[0],
        settings: base.settings || {
          theme: "tournament",
          soundEnabled: true,
          coachMode: true,
          boardStyle: "tournament"
        },
        createdAt: base.createdAt || new Date().toISOString()
      };

      const existingIndex = users.findIndex(
        (u) => u.id === uid || u.uid === uid || (verifiedEmail && u.email.toLowerCase() === verifiedEmail)
      );
      if (existingIndex !== -1) {
        users[existingIndex] = mergedUser;
      } else {
        users.push(mergedUser);
      }
      saveUsersDB(users);

      // Persist to Firestore with timeout guard so profile is synced without hanging offline
      try {
        await withTimeout(saveUserProfileToFirestore(mergedUser), 4000, "Firestore sync timed out");
      } catch (err) {
        console.warn("Firestore sync warning during Google sign-in:", err);
      }

      syncLegacyUserProfile(mergedUser);

      const { passwordHash: _, ...userWithoutHash } = mergedUser;
      const token = `google_token_${uid}_${Date.now()}`;
      const session: AuthSession = {
        token,
        user: userWithoutHash,
        expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
      };

      localStorage.setItem(CURRENT_SESSION_KEY, JSON.stringify(session));
      localStorage.setItem("chessmaster_logged_in", "true");

      console.log("[GoogleAuth] Existing profile loaded");
      return { user: userWithoutHash, token };
    }

    // 2. Brand New First-Time Google User
    const initialCandidate = displayName || extractUsernameFromEmail(verifiedEmail);
    const uniqueUsername = await generateUniqueUsername(initialCandidate);
    const avatar =
      photoURL ||
      `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(uniqueUsername)}`;

    const newGoogleUser: StoredUser = {
      id: uid,
      uid: uid,
      username: uniqueUsername,
      email: verifiedEmail || `${uniqueUsername.toLowerCase()}@gmail.com`,
      passwordHash: "google_authenticated_oauth",
      profilePicture: avatar,
      profileImageUrl: avatar,
      level: 1,
      xp: 0,
      coins: 0,
      rating: 1200,
      elo: 1200,
      puzzleElo: 1200,
      ratings: { bullet: 1200, blitz: 1200, rapid: 1200, classical: 1200 },
      modeStats: {
        bullet: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
        blitz: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
        rapid: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 },
        classical: { games: 0, wins: 0, losses: 0, draws: 0, highest: 1200 }
      },
      matchHistory: [],
      highestRating: 1200,
      gamesPlayed: 0,
      gamesWon: 0,
      gamesLost: 0,
      wins: 0,
      losses: 0,
      draws: 0,
      puzzlesSolved: 0,
      lessonsCompleted: 0,
      gambitsCompleted: 0,
      trapsCompleted: 0,
      streak: 0,
      longestStreak: 0,
      bestStreak: 0,
      lastActivityDate: null,
      streakStartedAt: null,
      unlockedBadges: [],
      lastActiveDate: new Date().toISOString().split("T")[0],
      settings: {
        theme: "tournament",
        soundEnabled: true,
        coachMode: true,
        boardStyle: "tournament"
      },
      createdAt: new Date().toISOString()
    };

    users.push(newGoogleUser);
    saveUsersDB(users);

    try {
      await withTimeout(saveUserProfileToFirestore(newGoogleUser), 4000, "Firestore sync timed out");
    } catch (err) {
      console.warn("Firestore sync warning during new Google user creation:", err);
    }

    syncLegacyUserProfile(newGoogleUser);

    const { passwordHash: _, ...userWithoutHash } = newGoogleUser;
    const token = `google_token_${uid}_${Date.now()}`;
    const session: AuthSession = {
      token,
      user: userWithoutHash,
      expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000
    };

    localStorage.setItem(CURRENT_SESSION_KEY, JSON.stringify(session));
    localStorage.setItem("chessmaster_logged_in", "true");

    console.log("[GoogleAuth] New profile created and loaded");
    return { user: userWithoutHash, token };
  })();

  inFlightProfileSyncs.set(uid, syncPromise);
  try {
    return await syncPromise;
  } finally {
    inFlightProfileSyncs.delete(uid);
  }
}

/**
 * Detects if the current environment is Android Capacitor native app,
 * an Android native shell, or mobile WebView bridge.
 * Returns false on standard web browsers to prevent web fallback popup errors.
 */
export function isAndroidMobilePlatform(): boolean {
  if (typeof window === "undefined") return false;
  try {
    // 1. Android JavaScript Bridge injected by native app wrapper
    if ((window as any).AndroidBridge?.signInWithGoogle || (window as any).AndroidGoogleAuth?.signIn) {
      return true;
    }
    // 2. Capacitor native platform running on Android (strictly native, not web)
    const cap = (window as any).Capacitor || Capacitor;
    if (typeof cap?.isNativePlatform === "function" && cap.isNativePlatform()) {
      return true;
    }
    // 3. Native app protocol scheme
    if (window.location?.protocol === "capacitor:" || window.location?.protocol === "ionic:") {
      return true;
    }
  } catch {
    // ignore
  }
  return false;
}

/**
 * Retrieves the effective Google Web Client ID for OAuth / ID token verification.
 * Only returns valid, non-placeholder credentials from environment, firebaseConfig, or window globals.
 * If not explicitly configured, returns undefined to allow Android's native
 * google-services.json (R.string.default_web_client_id) to be used automatically.
 * NEVER returns fabricated or fake strings like ${senderId}-...
 */
export function getEffectiveGoogleClientId(): string | undefined {
  const envWebClientId = (import.meta as any).env?.VITE_GOOGLE_CLIENT_ID;
  const envServerClientId = (import.meta as any).env?.VITE_GOOGLE_SERVER_CLIENT_ID;
  const configClientId = (firebaseConfig as any)?.oAuthClientId;
  const windowClientId = typeof window !== "undefined" 
    ? ((window as any).GOOGLE_CLIENT_ID || (window as any).GOOGLE_WEB_CLIENT_ID) 
    : undefined;

  const raw = envWebClientId || envServerClientId || configClientId || windowClientId;
  if (raw && typeof raw === "string" && raw.trim().length > 0) {
    const trimmed = raw.trim();
    // Verify it's a real format and not a placeholder or fake concat
    if (
      trimmed.includes(".apps.googleusercontent.com") &&
      !trimmed.includes("YOUR_") &&
      !trimmed.includes("dummy") &&
      !trimmed.startsWith("123456789")
    ) {
      return trimmed;
    }
  }

  return undefined;
}

/**
 * Concurrency flag to prevent duplicate simultaneous sign-in requests
 */
let isGoogleSignInRunning = false;

/**
 * Checks whether an error from Firebase Auth or Android Google Sign-In represents
 * explicit user cancellation (closing the account picker / popup).
 */
export function isGoogleAuthCancelledError(error: any): boolean {
  const errObj = typeof error === "object" && error !== null ? error : {};
  const msg = String(error?.message || errObj.error || errObj.type || error || "");
  const code = String(error?.code || errObj.code || "");
  let errorStr = "";
  try {
    errorStr = typeof error === "object" ? JSON.stringify(error) : String(error);
  } catch {
    errorStr = msg;
  }

  const lowerMsg = msg.toLowerCase();
  const lowerStr = errorStr.toLowerCase();

  return (
    code === "12501" ||
    code === "16" ||
    code === "auth/popup-closed-by-user" ||
    code === "auth/cancelled-popup-request" ||
    code === "auth/user-cancelled" ||
    msg === "POPUP_CANCELLED" ||
    msg.includes("POPUP_CANCELLED") ||
    msg.includes("popup_closed_by_user") ||
    msg.includes("popup-closed-by-user") ||
    msg.includes("cancelled-popup-request") ||
    msg.includes("closed-by-user") ||
    msg.includes("12501") ||
    msg.includes("user_cancel") ||
    lowerMsg.includes("user cancelled") ||
    lowerMsg.includes("user canceled") ||
    lowerMsg.includes("cancellationexception") ||
    lowerMsg.includes("request canceled") ||
    lowerMsg.includes("request cancelled") ||
    lowerMsg.includes("sign in was cancelled") ||
    lowerMsg.includes("sign-in was cancelled") ||
    lowerMsg.includes("canceled by user") ||
    lowerMsg.includes("cancelled by user") ||
    lowerMsg.includes("authorization canceled") ||
    lowerStr.includes("popup_closed_by_user") ||
    lowerStr.includes("12501")
  );
}

/**
 * Translates Firebase / Google OAuth / Android Sign-In errors into clear, accurate messages.
 */
function formatGoogleAuthError(error: any): Error {
  if (isGoogleAuthCancelledError(error)) {
    return new Error("POPUP_CANCELLED");
  }

  const errObj = typeof error === "object" && error !== null ? error : {};
  const errCode = String(error?.code || errObj.code || "");
  const errMsg = String(error?.message || errObj.error || errObj.type || error || "");
  const lowerMsg = errMsg.toLowerCase();

  if (
    errCode === "auth/unauthorized-domain" ||
    lowerMsg.includes("unauthorized-domain")
  ) {
    const host = typeof window !== "undefined" ? window.location.hostname : "this domain";
    return new Error(
      `Domain "${host}" is not authorized for Google Sign-In in Firebase Console. Add "${host}" under Authentication → Settings → Authorized domains.`
    );
  }

  if (
    errCode === "auth/operation-not-allowed" ||
    lowerMsg.includes("operation-not-allowed")
  ) {
    return new Error(
      "Google Sign-In is not enabled in Firebase Authentication. Enable the Google provider in Firebase Console."
    );
  }

  if (errCode === "auth/account-exists-with-different-credential") {
    return new Error(
      "An account with this email already exists using a different sign-in method."
    );
  }

  if (errCode === "auth/user-disabled") {
    return new Error("This ChessZen account has been disabled.");
  }

  if (
    errCode === "auth/invalid-credential" ||
    errCode === "auth/invalid-verification-id" ||
    lowerMsg.includes("invalid-credential")
  ) {
    return new Error(
      "Invalid Google authentication credential or project OAuth mismatch. Verify google-services.json matches your Firebase project."
    );
  }

  if (
    errCode === "401" ||
    lowerMsg.includes("invalid_client") ||
    lowerMsg.includes("oauth client was not found")
  ) {
    return new Error(
      `Google OAuth Client ID error (401: invalid_client). Verify Web Client ID and SHA-1 in Firebase Console (${(firebaseConfig as any).projectId}).`
    );
  }

  if (
    errCode === "10" ||
    errCode === "12500" ||
    lowerMsg.includes("developer_error") ||
    lowerMsg.includes("apiexception: 10") ||
    lowerMsg.includes("status code: 10") ||
    lowerMsg.includes("12500") ||
    lowerMsg.includes("nocredentialexception") ||
    lowerMsg.includes("no credentials available")
  ) {
    return new Error(
      `Google Sign-In Android configuration error (${errCode || "DEVELOPER_ERROR / NoCredential"}). Ensure Android package name "com.aistudio.chesszen.app", SHA-1/SHA-256 fingerprints, and the latest google-services.json from Firebase project "${(firebaseConfig as any).projectId}" are configured.`
    );
  }

  if (
    lowerMsg.includes("play services") ||
    lowerMsg.includes("service_version_update_required") ||
    lowerMsg.includes("service_missing") ||
    lowerMsg.includes("service_disabled")
  ) {
    return new Error(
      "Google Play Services is unavailable or needs an update on this Android device. Please update Google Play Services and try again."
    );
  }

  if (
    errCode === "auth/network-request-failed" ||
    errCode === "7" ||
    lowerMsg.includes("network_error") ||
    lowerMsg.includes("network")
  ) {
    return new Error("Unable to sign in. Check your internet connection and try again.");
  }

  if (
    errCode === "auth/popup-blocked" ||
    errCode === "popup_blocked_by_browser" ||
    lowerMsg.includes("popup-blocked") ||
    lowerMsg.includes("popup_blocked_by_browser")
  ) {
    return new Error(
      "Google Sign-In popup was blocked by your browser. Please allow popups for ChessZen and try again."
    );
  }

  return new Error(errMsg || "Google Sign-In failed. Please try again.");
}

/**
 * Direct ID Token Authentication with Firebase (Used by Android Native Google Sign-In,
 * Credential Manager, Capacitor Plugins, or GIS).
 */
export async function signInWithGoogleIdToken(
  idToken: string,
  accessToken?: string
): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  try {
    console.log("[GoogleAuth] Exchanging Google ID token for Firebase credential");
    const credential = GoogleAuthProvider.credential(idToken, accessToken);
    const authResult = await withTimeout(
      signInWithCredential(auth, credential),
      25000,
      "Unable to complete sign-in. Please check your internet connection."
    );
    if (!authResult || !authResult.user || !authResult.user.uid) {
      throw new Error("Firebase Google authentication failed. Please try again.");
    }
    console.log("[GoogleAuth] Firebase authentication successful:", authResult.user.uid);
    const session = await processAuthenticatedFirebaseUser(authResult.user);
    console.log("[GoogleAuth] Auth state authenticated");
    return session;
  } catch (error: any) {
    console.error("Firebase signInWithCredential error:", error);
    throw formatGoogleAuthError(error);
  }
}

/**
 * Native Android Google Sign-In Flow.
 * Uses @capacitor-firebase/authentication native Google Account Chooser (Credential Manager with
 * GoogleSignInClient fallback), extracts the Google ID token, and exchanges it with Firebase JS SDK
 * signInWithCredential so Auth & Firestore share the exact same Firebase project session.
 * Absolutely NEVER uses signInWithPopup or signInWithRedirect on Android.
 */
export async function performAndroidNativeGoogleAuth(): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  console.log("[GoogleAuth] Android native platform detected");

  // 1. Check custom Android JavascriptInterface bridge if provided by a native wrapper
  if ((window as any).AndroidBridge?.signInWithGoogle || (window as any).AndroidGoogleAuth?.signIn) {
    try {
      console.log("[GoogleAuth] Opening Android bridge account chooser");
      const bridge = (window as any).AndroidBridge || (window as any).AndroidGoogleAuth;
      const bridgePromise = new Promise<string>((resolve, reject) => {
        (window as any)._onAndroidGoogleAuthSuccess = (token: string) => resolve(token);
        (window as any)._onAndroidGoogleAuthError = (errMsg: string) => reject(new Error(errMsg));
        bridge.signInWithGoogle();
      });
      const idToken = await withTimeout(bridgePromise, 35000, "Google Sign-In timed out. Please try again.");
      if (!idToken) {
        throw new Error("Unable to complete Google Sign-In. Please try again.");
      }
      console.log("[GoogleAuth] Bridge ID token received");
      return await signInWithGoogleIdToken(idToken);
    } catch (bridgeErr: any) {
      if (isGoogleAuthCancelledError(bridgeErr)) {
        throw new Error("POPUP_CANCELLED");
      }
      console.warn("Android bridge auth note:", bridgeErr);
    }
  }

  // 2. Use Official @capacitor-firebase/authentication Plugin
  // Note: Omit `scopes` during initial sign-in so Credential Manager does not trigger a
  // secondary AuthorizationClient offline-access prompt; ID token already provides uid/email/name/photo.
  const invokeNativeGoogleSignIn = async (useCredentialManager: boolean) => {
    console.log(`[GoogleAuth] Opening native Google account chooser (useCredentialManager=${useCredentialManager})`);
    return await withTimeout(
      FirebaseAuthentication.signInWithGoogle({
        useCredentialManager,
        skipNativeAuth: true
      }),
      45000,
      "Google Sign-In timed out. Please try again."
    );
  };

  try {
    let result;
    try {
      result = await invokeNativeGoogleSignIn(true);
    } catch (cmErr: any) {
      if (isGoogleAuthCancelledError(cmErr)) {
        throw cmErr;
      }
      const cmMsg = String(cmErr?.message || cmErr || "").toLowerCase();
      // On older Android / missing Credential Manager / emulator cases, fall back to GoogleSignInClient intent
      const shouldFallbackToLegacyIntent =
        cmMsg.includes("nocredential") ||
        cmMsg.includes("no credential") ||
        cmMsg.includes("unsupported") ||
        cmMsg.includes("credentialmanager") ||
        cmMsg.includes("getcredential") ||
        cmMsg.includes("16");

      if (!shouldFallbackToLegacyIntent) {
        throw cmErr;
      }

      console.warn("[GoogleAuth] Credential Manager unavailable/no credential, falling back to GoogleSignInClient intent:", cmMsg);
      result = await invokeNativeGoogleSignIn(false);
    }

    console.log("[GoogleAuth] Native Google account selected");
    const idToken = result.credential?.idToken;
    const accessToken = result.credential?.accessToken;

    if (idToken) {
      console.log("[GoogleAuth] Native Google ID token obtained");
      return await signInWithGoogleIdToken(idToken, accessToken);
    }

    if (result.user && result.user.uid) {
      console.log("[GoogleAuth] Native Firebase user available:", result.user.uid);
      return await processAuthenticatedFirebaseUser({
        uid: result.user.uid,
        email: result.user.email || "",
        displayName: result.user.displayName || "",
        photoURL: result.user.photoUrl || (result.user as any).photoURL || ""
      });
    }

    throw new Error("Unable to retrieve Google ID token. Please verify SHA-1 and google-services.json.");
  } catch (err: any) {
    if (isGoogleAuthCancelledError(err)) {
      console.log("[GoogleAuth] Native account selection cancelled by user");
      throw new Error("POPUP_CANCELLED");
    }
    console.error("Android Native Google Sign-In error:", err);
    throw formatGoogleAuthError(err);
  }
}

/**
 * Universal Android / Mobile / Web Google Authentication Flow.
 * - Android/Capacitor: Exclusively uses Native Google Account Chooser + ID token exchange.
 * - Web: Uses Firebase signInWithPopup with prompt=select_account, with automatic
 *   signInWithRedirect fallback if a browser blocks popups outside an iframe.
 */
export async function signInWithGoogle(): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string }> {
  if (isGoogleSignInRunning) {
    throw new Error("Sign-in is already in progress.");
  }
  isGoogleSignInRunning = true;

  try {
    if (isAndroidMobilePlatform()) {
      return await performAndroidNativeGoogleAuth();
    }

    // Standard Desktop / Mobile Web Browser Flow (Firebase Popup)
    googleProvider.setCustomParameters({
      prompt: "select_account"
    });

    console.log("[GoogleAuth] Account chooser popup opening");
    const popupPromise = signInWithPopup(auth, googleProvider);
    const authResult = await withTimeout(
      popupPromise,
      45000,
      "Google Sign-In request timed out. Please try again."
    );

    if (!authResult || !authResult.user || !authResult.user.uid) {
      throw new Error("Google Sign-In failed. Please try again.");
    }

    console.log("[GoogleAuth] Account selected, UID:", authResult.user.uid);
    const session = await processAuthenticatedFirebaseUser(authResult.user);
    console.log("[GoogleAuth] Auth state authenticated");
    return session;
  } catch (error: any) {
    if (isGoogleAuthCancelledError(error)) {
      console.log("[GoogleAuth] Account selection cancelled by user");
      throw new Error("POPUP_CANCELLED");
    }

    const errCode = String(error?.code || "");
    const errMsg = String(error?.message || "");
    const isPopupBlocked =
      errCode === "auth/popup-blocked" ||
      errCode === "auth/operation-not-supported-in-this-environment" ||
      errMsg.includes("popup-blocked") ||
      errMsg.includes("popup_blocked_by_browser");

    // On top-level mobile/desktop browsers where popups are blocked, fall back to redirect
    const isInIframe = typeof window !== "undefined" && window.self !== window.top;
    if (isPopupBlocked && !isInIframe) {
      console.warn("[GoogleAuth] Popup blocked; falling back to signInWithRedirect");
      await signInWithRedirect(auth, googleProvider);
      // Navigation occurs; return a pending promise that won't flash an error before redirect
      return await new Promise(() => {});
    }

    throw formatGoogleAuthError(error);
  } finally {
    isGoogleSignInRunning = false;
  }
}

/**
 * Checks if the user just returned from a Firebase signInWithRedirect Google flow.
 */
export async function checkPendingRedirectAuth(): Promise<{ user: Omit<StoredUser, 'passwordHash'>; token: string } | null> {
  if (isAndroidMobilePlatform()) {
    return null;
  }
  try {
    const result = await getRedirectResult(auth);
    if (result && result.user) {
      console.log("[GoogleAuth] Redirect authentication result received for UID:", result.user.uid);
      return await processAuthenticatedFirebaseUser(result.user);
    }
    return null;
  } catch (error: any) {
    if (isGoogleAuthCancelledError(error)) {
      return null;
    }
    const errCode = String(error?.code || "");
    // Ignore benign storage/no-redirect errors on initial load
    if (
      errCode === "auth/no-auth-event" ||
      errCode === "auth/web-storage-unsupported" ||
      errCode === "auth/missing-initial-state"
    ) {
      return null;
    }
    console.warn("[GoogleAuth] getRedirectResult note:", error);
    return null;
  }
}

// Forgot Password OTP Flow
export interface OTPRecord {
  email: string;
  code: string;
  expiresAt: number;
}

export function generateOTPForEmail(email: string): string {
  const users = getStoredUsers();
  const cleanEmail = email.trim().toLowerCase();
  const user = users.find((u) => u.email.toLowerCase() === cleanEmail);

  if (!user) {
    throw new Error("No account registered with this email address.");
  }

  // Generate 6-digit OTP code
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const record: OTPRecord = {
    email: cleanEmail,
    code,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 mins
  };

  localStorage.setItem(OTP_STORE_KEY + "_" + cleanEmail, JSON.stringify(record));
  return code;
}

export function verifyOTPCode(email: string, code: string): boolean {
  const cleanEmail = email.trim().toLowerCase();
  const raw = localStorage.getItem(OTP_STORE_KEY + "_" + cleanEmail);
  if (!raw) throw new Error("OTP expired or not found. Please request a new code.");

  const record: OTPRecord = JSON.parse(raw);
  if (Date.now() > record.expiresAt) {
    localStorage.removeItem(OTP_STORE_KEY + "_" + cleanEmail);
    throw new Error("OTP verification code has expired. Please request a new code.");
  }

  if (record.code !== code.trim()) {
    throw new Error("Invalid verification code. Please check and try again.");
  }

  return true;
}

export async function resetPasswordWithVerifiedOTP(
  email: string,
  code: string,
  newPassword: string
): Promise<boolean> {
  verifyOTPCode(email, code);

  const cleanEmail = email.trim().toLowerCase();
  const users = getStoredUsers();
  const userIndex = users.findIndex((u) => u.email.toLowerCase() === cleanEmail);

  if (userIndex === -1) {
    throw new Error("User account not found.");
  }

  const newHash = await hashPassword(newPassword);
  users[userIndex].passwordHash = newHash;
  saveUsersDB(users);

  // Clear OTP record
  localStorage.removeItem(OTP_STORE_KEY + "_" + cleanEmail);
  return true;
}

// Session Management
export function getCurrentAuthSession(): AuthSession | null {
  const raw = localStorage.getItem(CURRENT_SESSION_KEY);
  if (!raw) return null;
  try {
    const session: AuthSession = JSON.parse(raw);
    if (Date.now() > session.expiresAt) {
      logoutUser();
      return null;
    }
    return session;
  } catch {
    logoutUser();
    return null;
  }
}

export function logoutUser(): void {
  localStorage.removeItem(CURRENT_SESSION_KEY);
  localStorage.removeItem("chessmaster_logged_in");
  localStorage.setItem("chessmaster_logged_in", "false");
  localStorage.removeItem("chessmaster_user_profile");
  
  // Sign out from Firebase
  try {
    signOut(auth).catch(() => {});
  } catch {
    // ignore
  }

  // Sign out from Capacitor FirebaseAuthentication plugin if present
  try {
    FirebaseAuthentication.signOut().catch(() => {});
  } catch {
    // ignore
  }

  // Disable GIS auto-select if present
  try {
    if ((window as any).google?.accounts?.id?.disableAutoSelect) {
      (window as any).google.accounts.id.disableAutoSelect();
    }
  } catch {
    // ignore
  }
}

// Helper to keep App's existing localStorage structure synced
function syncLegacyUserProfile(user: StoredUser): void {
  const savedRating = user.rating ?? user.elo ?? 1200;
  const legacyProfile = {
    id: user.id,
    uid: user.id,
    username: user.username,
    email: user.email,
    isGuest: false,
    elo: savedRating,
    rating: savedRating,
    puzzleElo: user.puzzleElo ?? 1200,
    ratings: user.ratings || { bullet: 1200, blitz: 1200, rapid: 1200, classical: 1200 },
    modeStats: user.modeStats,
    matchHistory: user.matchHistory || [],
    puzzleProgress: (user as any).puzzleProgress || {},
    gambitProgress: (user as any).gambitProgress || {},
    boardTheme: (user as any).boardTheme || user.settings?.boardStyle || "tournament",
    settings: user.settings,
    profilePicture: user.profilePicture,
    profileImageUrl: user.profilePicture,
    highestRating: user.highestRating || savedRating,
    gamesPlayed: user.gamesPlayed || 0,
    wins: user.wins || 0,
    losses: user.losses || 0,
    draws: user.draws || 0,
    streak: user.streak ?? 0,
    longestStreak: user.longestStreak ?? user.bestStreak ?? 0,
    bestStreak: user.bestStreak ?? user.longestStreak ?? 0,
    lastActivityDate: user.lastActivityDate ?? null,
    streakStartedAt: user.streakStartedAt ?? null,
    level: user.level || 1,
    xp: user.xp || 0,
    coins: user.coins || 0,
    unlockedBadges: user.unlockedBadges || [],
    lastActiveDate: user.lastActiveDate ?? null
  };
  localStorage.setItem("chessmaster_user_profile", JSON.stringify(legacyProfile));

  // Sync to registered users array for existing components
  const rawReg = localStorage.getItem("chessmaster_registered_users");
  let regUsers = rawReg ? JSON.parse(rawReg) : [];
  const idx = regUsers.findIndex((u: any) => u.email.toLowerCase() === user.email.toLowerCase() || (u.profile && u.profile.id === user.id));
  if (idx !== -1) {
    regUsers[idx].username = user.username;
    regUsers[idx].profile = legacyProfile;
  } else {
    regUsers.push({
      id: user.id,
      email: user.email,
      username: user.username,
      password: "hashed_in_auth_service",
      profile: legacyProfile
    });
  }
  localStorage.setItem("chessmaster_registered_users", JSON.stringify(regUsers));
}

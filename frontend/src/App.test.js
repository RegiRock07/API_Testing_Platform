import { render, screen } from "@testing-library/react";
import App from "./App";

// No real Firebase in tests: report "signed out" so App shows the login screen.
jest.mock("./firebase", () => ({
  onAuth: (callback) => { callback(null); return () => {}; },
  signInWithGoogle: jest.fn(),
  signOut: jest.fn(),
  getIdToken: jest.fn(),
}));

test("renders the login screen when signed out", async () => {
  render(<App />);
  expect(await screen.findByRole("button", { name: /continue with google/i })).toBeInTheDocument();
  expect(screen.getByText(/sign in to continue/i)).toBeInTheDocument();
});

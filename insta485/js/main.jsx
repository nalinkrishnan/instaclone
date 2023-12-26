import React from "react";
import { createRoot } from "react-dom/client";
import Posts from "./posts";

// Create a root
const root = createRoot(document.getElementById("reactEntry"));

// This method is only called once
// Insert the post component into the DOM
root.render(<Posts url="/api/v1/posts/" />);

// sudo apt-get install nodejs npm
// npx webpack
